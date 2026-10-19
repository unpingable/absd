#![cfg_attr(target_os = "absd", feature(restricted_std))]
//! Dedicated qualification probe: unchanged DHCP owner and original deadline.
use absd_net::{FRAME_MAX, Link, LinkReading};
use std::{cell::RefCell, fmt::Write as _, rc::Rc};

#[derive(Default)]
struct Observations {
    start_ms: Option<u64>,
    rx: usize,
    tx: usize,
    dropped: bool,
    overflow: bool,
}
struct Observed<L: Link, F: FnMut(&str)> {
    link: L,
    observation: Rc<RefCell<Observations>>,
    emit: F,
    records: usize,
}
impl<L: Link, F: FnMut(&str)> Observed<L, F> {
    fn frame(&mut self, direction: &str, start: u64, end: u64, status: i64, bytes: &[u8]) {
        // Observation bounds refuse a qualification claim, never alter Link I/O.
        if self.records >= 32 || bytes.len() > FRAME_MAX {
            self.observation.borrow_mut().overflow = true;
            return;
        }
        self.records += 1;
        let mut hex = String::with_capacity(bytes.len() * 2);
        for byte in bytes {
            write!(&mut hex, "{byte:02x}").unwrap();
        }
        (self.emit)(&format!(
            "DHCP REFUSAL FRAME direction={direction} start_ms={start} end_ms={end} status={status} length={} hex={hex}",
            bytes.len()
        ));
    }
}
impl<L: Link, F: FnMut(&str)> Link for Observed<L, F> {
    fn mac(&self) -> [u8; 6] {
        self.link.mac()
    }
    fn send(&mut self, bytes: &[u8]) -> Result<(), i64> {
        let start = self.link.now_ms();
        let result = self.link.send(bytes);
        let end = self.link.now_ms();
        self.observation.borrow_mut().tx += 1;
        self.frame("tx", start, end, result.err().unwrap_or(0), bytes);
        result
    }
    fn receive(&mut self, bytes: &mut [u8; FRAME_MAX], timeout: u64) -> Result<Option<usize>, i64> {
        let start = self.link.now_ms();
        let result = self.link.receive(bytes, timeout);
        let end = self.link.now_ms();
        if let Ok(Some(n)) = result {
            self.observation.borrow_mut().rx += 1;
            if n <= bytes.len() {
                self.frame("rx", start, end, 0, &bytes[..n]);
            } else {
                self.observation.borrow_mut().overflow = true;
            }
        }
        result
    }
    fn now_ms(&self) -> u64 {
        let now = self.link.now_ms();
        self.observation.borrow_mut().start_ms.get_or_insert(now);
        now
    }
    fn pause(&self, ms: u64) {
        self.link.pause(ms);
    }
    fn link_up(&self) -> bool {
        self.link.link_up()
    }
    fn disabled(&self) -> bool {
        self.link.disabled()
    }
    fn read(&self) -> Option<LinkReading> {
        self.link.read()
    }
}
impl<L: Link, F: FnMut(&str)> Drop for Observed<L, F> {
    fn drop(&mut self) {
        let mut observed = self.observation.borrow_mut();
        observed.dropped = true;
        (self.emit)(&format!(
            "DHCP REFUSAL LINK DROP now_ms={} rx={} tx={} overflow={}",
            self.link.now_ms(),
            observed.rx,
            observed.tx,
            observed.overflow
        ));
    }
}

#[cfg(target_os = "absd")]
fn main() -> std::process::ExitCode {
    use absd_net::{
        NicLink,
        dhcp::{ACQUIRE_MS, Error, Owner, Policy},
    };
    absd_runtime::link_anchor();
    let nic = match NicLink::from_startup() {
        Ok(nic) => nic,
        Err(error) => {
            println!("DHCP REFUSAL SETUP ERROR {error:?}");
            return std::process::ExitCode::from(1);
        }
    };
    let observations = Rc::new(RefCell::new(Observations::default()));
    let link = Observed {
        link: nic,
        observation: observations.clone(),
        emit: |line: &str| println!("{line}"),
        records: 0,
    };
    println!("DHCP REFUSAL BEGIN acquire_ms={ACQUIRE_MS} child=not-started");
    let result = Owner::acquire(link, Policy::fixture());
    let ended = absd_runtime::boot_millis();
    match result {
        Err(Error::Timeout) => {
            let observation = observations.borrow();
            let Some(start) = observation.start_ms else {
                return std::process::ExitCode::from(1);
            };
            let Some(deadline) = start.checked_add(ACQUIRE_MS) else {
                return std::process::ExitCode::from(1);
            };
            println!(
                "DHCP REFUSAL END error=Timeout start_ms={start} deadline_ms={deadline} ended_ms={ended} dropped={} overflow={} rx={} tx={} child=not-started",
                observation.dropped, observation.overflow, observation.rx, observation.tx
            );
            if ended >= deadline
                && observation.dropped
                && !observation.overflow
                && observation.tx > 0
            {
                std::process::ExitCode::SUCCESS
            } else {
                std::process::ExitCode::from(1)
            }
        }
        Err(error) => {
            println!("DHCP REFUSAL UNEXPECTED ERROR {error:?}");
            std::process::ExitCode::from(1)
        }
        Ok(mut owner) => {
            owner.retire();
            println!("DHCP REFUSAL UNEXPECTED ACTIVATION");
            std::process::ExitCode::from(1)
        }
    }
}
#[cfg(not(target_os = "absd"))]
fn main() {
    panic!("native qualification probe only");
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::Cell;
    struct Fixture {
        clock: Rc<Cell<u64>>,
        sent: Rc<RefCell<Vec<Vec<u8>>>>,
        input: Option<Vec<u8>>,
        fail: bool,
    }
    impl Link for Fixture {
        fn mac(&self) -> [u8; 6] {
            [0x52, 0x54, 0, 0x12, 0x34, 0x56]
        }
        fn send(&mut self, b: &[u8]) -> Result<(), i64> {
            self.sent.borrow_mut().push(b.to_vec());
            if self.fail { Err(-5) } else { Ok(()) }
        }
        fn receive(&mut self, b: &mut [u8; FRAME_MAX], timeout: u64) -> Result<Option<usize>, i64> {
            self.clock.set(self.clock.get() + timeout);
            if let Some(input) = self.input.take() {
                b[..input.len()].copy_from_slice(&input);
                Ok(Some(input.len()))
            } else {
                Ok(None)
            }
        }
        fn now_ms(&self) -> u64 {
            self.clock.get()
        }
        fn pause(&self, ms: u64) {
            self.clock.set(self.clock.get() + ms);
        }
        fn read(&self) -> Option<LinkReading> {
            if self.fail {
                None
            } else {
                Some(LinkReading {
                    link_up: true,
                    disabled: false,
                    rx_missed: 0,
                })
            }
        }
    }
    fn fixture(
        fail: bool,
    ) -> (
        Observed<Fixture, impl FnMut(&str)>,
        Rc<RefCell<Observations>>,
        Rc<RefCell<Vec<String>>>,
    ) {
        let observed = Rc::new(RefCell::new(Observations::default()));
        let lines = Rc::new(RefCell::new(Vec::new()));
        let log = lines.clone();
        (
            Observed {
                link: Fixture {
                    clock: Rc::new(Cell::new(100)),
                    sent: Rc::new(RefCell::new(Vec::new())),
                    input: Some(vec![0, 1, 254, 255]),
                    fail,
                },
                observation: observed.clone(),
                emit: move |line: &str| log.borrow_mut().push(line.to_owned()),
                records: 0,
            },
            observed,
            lines,
        )
    }
    #[test]
    fn observes_exact_bytes_without_changing_io_clock_or_first_effect_refusal() {
        let (mut link, observation, lines) = fixture(true);
        assert!(link.read().is_none());
        assert_eq!(link.now_ms(), 100);
        assert_eq!(observation.borrow().start_ms, Some(100));
        assert_eq!(link.send(&[1, 2, 3]), Err(-5));
        assert_eq!(&link.link.sent.borrow()[0], &[1, 2, 3]);
        let mut b = [0; FRAME_MAX];
        assert_eq!(link.receive(&mut b, 7), Ok(Some(4)));
        assert_eq!(&b[..4], &[0, 1, 254, 255]);
        assert_eq!(link.now_ms(), 107);
        assert_eq!(observation.borrow().start_ms, Some(100));
        drop(link);
        assert!(observation.borrow().dropped);
        assert!(lines.borrow()[0].contains("status=-5 length=3 hex=010203"));
        assert!(
            lines.borrow()[1].contains("start_ms=100 end_ms=107 status=0 length=4 hex=0001feff")
        );
    }
    #[test]
    fn exhausted_observation_budget_keeps_link_semantics_but_refuses_claim() {
        let (mut link, observation, lines) = fixture(false);
        for _ in 0..33 {
            assert_eq!(link.send(&[1]), Ok(()));
        }
        assert_eq!(link.link.sent.borrow().len(), 33);
        assert_eq!(lines.borrow().len(), 32);
        assert!(observation.borrow().overflow);
    }
    #[test]
    fn actual_owner_no_offer_exits_at_original_deadline_and_drops_link() {
        let (mut link, observation, _) = fixture(false);
        link.link.input = None;
        let result = absd_net::dhcp::Owner::acquire(link, absd_net::dhcp::Policy::fixture());
        assert!(matches!(result, Err(absd_net::dhcp::Error::Timeout)));
        let observed = observation.borrow();
        assert_eq!(observed.start_ms, Some(100));
        assert!(observed.dropped);
        assert!(observed.tx > 0);
        assert!(!observed.overflow);
    }
    struct OfferFixture {
        clock: Rc<Cell<u64>>,
        sent: Rc<RefCell<Vec<Vec<u8>>>>,
        input: Option<Vec<u8>>,
        mode: &'static str,
        offered: bool,
    }
    fn kind(frame: &[u8]) -> u8 {
        let mut at = 282;
        while frame[at] != 255 {
            let tag = frame[at];
            if tag == 0 {
                at += 1;
                continue;
            }
            let n = usize::from(frame[at + 1]);
            if tag == 53 {
                assert_eq!(n, 1);
                return frame[at + 2];
            }
            at += 2 + n;
        }
        panic!("missing outgoing DHCP type");
    }
    impl Link for OfferFixture {
        fn mac(&self) -> [u8; 6] {
            [0x52, 0x54, 0, 0x12, 0x34, 0x56]
        }
        fn now_ms(&self) -> u64 {
            self.clock.get()
        }
        fn pause(&self, ms: u64) {
            self.clock.set(self.clock.get() + ms);
        }
        fn send(&mut self, frame: &[u8]) -> Result<(), i64> {
            self.sent.borrow_mut().push(frame.to_vec());
            if !self.offered && kind(frame) == 1 {
                self.offered = true;
                let text = include_str!("../../fixtures/native-dhcp/captured-offer.hex").trim();
                let mut payload: Vec<u8> = text
                    .as_bytes()
                    .chunks_exact(2)
                    .map(|pair| u8::from_str_radix(std::str::from_utf8(pair).unwrap(), 16).unwrap())
                    .collect();
                assert_eq!(&payload[28..34], &self.mac());
                payload[4..8].copy_from_slice(&frame[46..50]);
                if self.mode == "wrong-xid" {
                    payload[4] ^= 1;
                    assert_ne!(&payload[4..8], &frame[46..50]);
                }
                payload[28..34].copy_from_slice(&self.mac());
                let mut at = 240;
                let mut end = 0;
                while at < payload.len() {
                    let tag = payload[at];
                    at += 1;
                    if tag == 0 {
                        continue;
                    }
                    if tag == 255 {
                        end = at - 1;
                        break;
                    }
                    let n = usize::from(payload[at]);
                    at += 1;
                    if tag == 54 && self.mode == "unauthorized" {
                        payload[at + 3] = 2;
                    }
                    at += n;
                }
                assert!(end > 240);
                if self.mode == "malformed" {
                    payload.splice(end..end, [53, 1, 2]);
                }
                let mut reply = vec![0; 42];
                reply[..6].fill(255);
                reply[6..12].copy_from_slice(&[0x52, 0x55, 0, 0, 3, 1]);
                reply[12..15].copy_from_slice(&[8, 0, 0x45]);
                reply[22..24].copy_from_slice(&[64, 17]);
                reply[26..30].copy_from_slice(&[192, 0, 2, 1]);
                reply[30..34].fill(255);
                reply[34..38].copy_from_slice(&[0, 67, 0, 68]);
                reply.extend_from_slice(&payload);
                let ip = (reply.len() - 14) as u16;
                let udp = (reply.len() - 34) as u16;
                reply[16..18].copy_from_slice(&ip.to_be_bytes());
                reply[38..40].copy_from_slice(&udp.to_be_bytes());
                let mut sum: u32 = reply[14..34]
                    .chunks_exact(2)
                    .map(|p| u32::from(u16::from_be_bytes([p[0], p[1]])))
                    .sum();
                while sum > 65535 {
                    sum = (sum & 65535) + (sum >> 16);
                }
                reply[24..26].copy_from_slice(&(!(sum as u16)).to_be_bytes());
                self.input = Some(reply);
            }
            Ok(())
        }
        fn receive(
            &mut self,
            bytes: &mut [u8; FRAME_MAX],
            _timeout: u64,
        ) -> Result<Option<usize>, i64> {
            if let Some(frame) = self.input.take() {
                bytes[..frame.len()].copy_from_slice(&frame);
                Ok(Some(frame.len()))
            } else {
                Ok(None)
            }
        }
    }
    fn assert_actual_offer_outcome(mode: &'static str) {
        let sent = Rc::new(RefCell::new(Vec::new()));
        let clock = Rc::new(Cell::new(100));
        let observations = Rc::new(RefCell::new(Observations::default()));
        let link = Observed {
            link: OfferFixture {
                clock: clock.clone(),
                sent: sent.clone(),
                input: None,
                mode,
                offered: false,
            },
            observation: observations.clone(),
            emit: |_: &str| {},
            records: 0,
        };
        let result = absd_net::dhcp::Owner::acquire(link, absd_net::dhcp::Policy::fixture());
        assert!(
            matches!(result, Err(absd_net::dhcp::Error::Timeout)),
            "{mode}"
        );
        let observation = observations.borrow();
        assert_eq!(observation.rx, 1);
        assert!(observation.dropped);
        assert!(!observation.overflow);
        assert_eq!(clock.get(), 100 + absd_net::dhcp::ACQUIRE_MS);
        let kinds: Vec<_> = sent.borrow().iter().map(|f| kind(f)).collect();
        assert_eq!(kinds[0], 1);
        if mode == "valid" {
            assert!(kinds.contains(&3));
        } else {
            assert!(kinds.len() > 1);
            assert!(kinds.iter().all(|k| *k == 1));
        }
    }

    #[test]
    fn actual_owner_refuses_captured_offer_mutations_and_accepts_calibration_to_request() {
        for mode in ["malformed", "unauthorized", "valid"] {
            assert_actual_offer_outcome(mode);
        }
    }

    #[test]
    fn actual_owner_wrong_xid_offer_preserves_original_deadline_and_never_requests() {
        // The same wire shape must advance to REQUEST with the current xid.
        // With only its xid changed, refusal must retain Selecting through
        // the second Discover and the original acquisition deadline. Merely
        // relying on smoltcp to discard it would leave the owner Requesting.
        assert_actual_offer_outcome("valid");
        assert_actual_offer_outcome("wrong-xid");
    }
}
