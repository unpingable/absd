//! Device-boundary controls; actual TCP segmentation is in routing/tests/tcp.rs.
use super::*;
use smoltcp::phy::{Device, TxToken as _};
use std::{cell::RefCell, rc::Rc};

#[derive(Default)]
struct Wire {
    incoming: VecDeque<Vec<u8>>,
    sent: Vec<Vec<u8>>,
}
struct End(Rc<RefCell<Wire>>);
impl Link for End {
    fn mac(&self) -> [u8; 6] {
        [2, 0, 0, 0, 0, 1]
    }
    fn now_ms(&self) -> u64 {
        1
    }
    fn pause(&self, _: u64) {}
    fn send(&mut self, b: &[u8]) -> Result<(), i64> {
        self.0.borrow_mut().sent.push(b.to_vec());
        Ok(())
    }
    fn receive(&mut self, b: &mut [u8; FRAME_MAX], _: u64) -> Result<Option<usize>, i64> {
        Ok(self.0.borrow_mut().incoming.pop_front().map(|f| {
            // An impossible reported length tests refusal before any slicing.
            if f.len() <= b.len() {
                b[..f.len()].copy_from_slice(&f);
            }
            f.len()
        }))
    }
}
fn stack(mtu: usize) -> (Rc<RefCell<Wire>>, Stack<End>) {
    let w = Rc::new(RefCell::new(Wire::default()));
    let s = Stack::open_with_ip_mtu(End(w.clone()), Config::qemu_user(), mtu).unwrap();
    (w, s)
}
#[test]
fn mtu_is_selected_before_interface_and_default_stays_1500() {
    for mtu in [1280, 1500] {
        let (_, s) = stack(mtu);
        assert_eq!(s.ip_mtu(), mtu);
        assert_eq!(s.port.capabilities().ip_mtu(), mtu);
        assert_eq!(s.port.capabilities().max_transmission_unit, mtu + 14);
        assert_eq!(s.port.rx.len(), FRAME_MAX);
        assert_eq!(s.port.tx.len(), FRAME_MAX);
    }
    let w = Rc::new(RefCell::new(Wire::default()));
    let s = Stack::open(End(w), Config::qemu_user()).unwrap();
    assert_eq!(s.ip_mtu(), 1500);
    assert_eq!(s.port.capabilities().max_transmission_unit, 1514);
}
#[test]
fn invalid_mtu_refuses_before_observing_the_link() {
    struct Untouched;
    impl Link for Untouched {
        fn mac(&self) -> [u8; 6] {
            panic!("invalid config inspected link")
        }
        fn now_ms(&self) -> u64 {
            panic!("invalid config inspected clock")
        }
        fn pause(&self, _: u64) {
            panic!("invalid config paused")
        }
        fn send(&mut self, _: &[u8]) -> Result<(), i64> {
            panic!("invalid config sent")
        }
        fn receive(&mut self, _: &mut [u8; FRAME_MAX], _: u64) -> Result<Option<usize>, i64> {
            panic!("invalid config received")
        }
    }
    for mtu in [0, 1279, 1281, 1499, 1501, usize::MAX] {
        assert!(matches!(
            Stack::open_with_ip_mtu(Untouched, Config::qemu_user(), mtu),
            Err(NetError::Config)
        ));
    }
}
#[test]
fn mtu_receive_refuses_whole_oversize_frames_without_truncating_or_diverting() {
    for mtu in [1280, 1500] {
        let (w, mut s) = stack(mtu);
        s.divert(Some(0x88b5));
        let frame = |length| {
            let mut f = vec![0x5a; length];
            f[12..14].copy_from_slice(&0x88b5u16.to_be_bytes());
            f
        };
        let exact = frame(mtu + 14);
        w.borrow_mut()
            .incoming
            .extend([frame(mtu + 15), exact.clone()]);
        assert_eq!(s.port.fill(0), Ok(false));
        assert_eq!(s.raw_receive(), Some(exact));
        assert_eq!(s.raw_receive(), None);
        assert_eq!(
            (
                s.stats().rx_frames,
                s.stats().rx_oversize,
                s.stats().raw_frames
            ),
            (2, 1, 1)
        );
        assert_eq!(s.stats().link_errors, 0);
    }
}
#[test]
fn mtu_tx_refuses_the_whole_emission_without_shortening_its_physical_scratch() {
    let (w, mut s) = stack(1280);
    let cap = 1280 + 14;
    let value = s
        .port
        .transmit(Instant::from_millis(1))
        .unwrap()
        .consume(cap + 1, |b| {
            assert_eq!(
                b.len(),
                cap + 1,
                "configured MTU must not truncate the emitter input"
            );
            b.fill(0x6b);
            37
        });
    assert_eq!(value, 37);
    assert!(w.borrow().sent.is_empty());
    assert_eq!(s.stats().tx_oversize, 1);
    assert_eq!(s.stats().tx_frames, 0);
    assert_eq!(s.stats().link_errors, 1);
    s.port
        .transmit(Instant::from_millis(1))
        .unwrap()
        .consume(cap, |b| b.fill(0x7c));
    assert_eq!(w.borrow().sent, vec![vec![0x7c; cap]]);
    assert_eq!((s.stats().tx_frames, s.stats().tx_oversize), (1, 1));
}

#[test]
fn raw_send_retains_its_distinct_owner_link_authority() {
    let (w, mut s) = stack(1280);
    let frame = vec![0x5a; FRAME_MAX];
    s.raw_send(&frame).unwrap();
    assert_eq!(w.borrow().sent, vec![frame]);
    assert_eq!(s.stats().tx_oversize, 0);
}
