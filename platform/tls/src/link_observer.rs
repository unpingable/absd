//! Fixture-local observation of successfully submitted TCP receive windows.
//!
//! Frames and link behavior pass through unchanged. This measures advertised
//! windows for one tuple, not internal queue occupancy or peer receipt.
use absd_net::{FRAME_MAX, Link, LinkReading};
use std::{cell::Cell, rc::Rc};

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct WindowObservation {
    pub latest_window: Option<u16>,
    pub ack_events: u64,
    pub zero_events: u64,
    pub reopen_events: u64,
    pub first_zero_ms: Option<u64>,
    pub last_zero_ms: Option<u64>,
    pub last_ack_ms: Option<u64>,
    pub clock_refused: bool,
    pub counters_saturated: bool,
}

#[derive(Clone)]
pub struct Observer(Rc<Cell<WindowObservation>>);
impl Observer {
    pub fn snapshot(&self) -> WindowObservation {
        self.0.get()
    }
}

pub struct ObservedLink<L> {
    inner: L,
    local_port: u16,
    observation: Observer,
}
impl<L: Link> ObservedLink<L> {
    pub fn new(inner: L, local_port: u16) -> (Self, Observer) {
        let observation = Observer(Rc::new(Cell::new(WindowObservation::default())));
        (
            Self {
                inner,
                local_port,
                observation: observation.clone(),
            },
            observation,
        )
    }

    fn submitted(&self, frame: &[u8]) {
        let Some(window) = window(frame, self.local_port) else {
            return;
        };
        let now = self.inner.now_ms();
        let mut record = self.observation.snapshot();
        if record.last_ack_ms.is_some_and(|last| now < last) {
            record.clock_refused = true;
        }
        let mut increment = |counter: &mut u64| match counter.checked_add(1) {
            Some(next) => *counter = next,
            None => record.counters_saturated = true,
        };
        increment(&mut record.ack_events);
        if window == 0 {
            increment(&mut record.zero_events);
            record.first_zero_ms.get_or_insert(now);
            record.last_zero_ms = Some(now);
        } else if record.latest_window == Some(0) {
            increment(&mut record.reopen_events);
        }
        record.latest_window = Some(window);
        record.last_ack_ms = Some(now);
        self.observation.0.set(record);
    }
}

impl<L: Link> Link for ObservedLink<L> {
    fn mac(&self) -> [u8; 6] {
        self.inner.mac()
    }
    fn send(&mut self, frame: &[u8]) -> Result<(), i64> {
        self.inner.send(frame)?;
        self.submitted(frame);
        Ok(())
    }
    fn receive(
        &mut self,
        buffer: &mut [u8; FRAME_MAX],
        timeout_ms: u64,
    ) -> Result<Option<usize>, i64> {
        self.inner.receive(buffer, timeout_ms)
    }
    fn now_ms(&self) -> u64 {
        self.inner.now_ms()
    }
    fn pause(&self, ms: u64) {
        self.inner.pause(ms);
    }
    fn link_up(&self) -> bool {
        self.inner.link_up()
    }
    fn disabled(&self) -> bool {
        self.inner.disabled()
    }
    fn read(&self) -> Option<LinkReading> {
        self.inner.read()
    }
}

fn window(frame: &[u8], local_port: u16) -> Option<u16> {
    if frame.len() < 54 || frame[12..14] != [0x08, 0x00] {
        return None;
    }
    let ip = &frame[14..];
    let ihl = usize::from(ip[0] & 15) * 4;
    let total = usize::from(u16::from_be_bytes([ip[2], ip[3]]));
    if ip[0] >> 4 != 4
        || ihl < 20
        || total < ihl + 20
        || total > ip.len()
        || ip[6] & 0x3f != 0
        || ip[7] != 0
        || ip[9] != 6
        || ip[12..16] != [10, 0, 2, 15]
        || ip[16..20] != [10, 0, 2, 2]
    {
        return None;
    }
    let tcp = &ip[ihl..total];
    let header = usize::from(tcp[12] >> 4) * 4;
    if header < 20
        || header > tcp.len()
        || tcp[13] & 0x10 == 0
        || tcp[13] & 0x04 != 0
        || tcp[..2] != local_port.to_be_bytes()
        || tcp[2..4] != 4443u16.to_be_bytes()
    {
        return None;
    }
    Some(u16::from_be_bytes([tcp[14], tcp[15]]))
}

#[cfg(test)]
mod tests {
    use super::*;

    struct Fake {
        now: Cell<u64>,
        fail: bool,
        sent: Vec<Vec<u8>>,
    }
    impl Link for Fake {
        fn mac(&self) -> [u8; 6] {
            [1; 6]
        }
        fn send(&mut self, bytes: &[u8]) -> Result<(), i64> {
            self.sent.push(bytes.to_vec());
            if self.fail { Err(-5) } else { Ok(()) }
        }
        fn receive(&mut self, _: &mut [u8; FRAME_MAX], _: u64) -> Result<Option<usize>, i64> {
            Ok(None)
        }
        fn now_ms(&self) -> u64 {
            self.now.get()
        }
        fn pause(&self, ms: u64) {
            self.now.set(self.now.get() + ms);
        }
        fn link_up(&self) -> bool {
            false
        }
        fn disabled(&self) -> bool {
            true
        }
        fn read(&self) -> Option<LinkReading> {
            None
        }
    }
    fn frame(value: u16) -> [u8; 54] {
        let mut bytes = [0; 54];
        bytes[12..14].copy_from_slice(&[8, 0]);
        bytes[14] = 0x45;
        bytes[16..18].copy_from_slice(&40u16.to_be_bytes());
        bytes[23] = 6;
        bytes[26..30].copy_from_slice(&[10, 0, 2, 15]);
        bytes[30..34].copy_from_slice(&[10, 0, 2, 2]);
        bytes[34..36].copy_from_slice(&7300u16.to_be_bytes());
        bytes[36..38].copy_from_slice(&4443u16.to_be_bytes());
        bytes[46] = 0x50;
        bytes[47] = 0x10;
        bytes[48..50].copy_from_slice(&value.to_be_bytes());
        bytes
    }
    #[test]
    fn submission_is_unchanged_and_failed_send_does_not_count() {
        let (mut link, observer) = ObservedLink::new(
            Fake {
                now: Cell::new(10),
                fail: true,
                sent: vec![],
            },
            7300,
        );
        assert_eq!(link.send(&frame(0)), Err(-5));
        assert_eq!(observer.snapshot().ack_events, 0);
        assert_eq!(link.inner.sent[0], frame(0));
        link.inner.fail = false;
        link.send(&frame(0)).unwrap();
        assert_eq!(observer.snapshot().first_zero_ms, Some(10));
        link.pause(2);
        link.send(&frame(1024)).unwrap();
        let record = observer.snapshot();
        assert_eq!(
            (record.ack_events, record.zero_events, record.reopen_events),
            (2, 1, 1)
        );
        assert_eq!(record.latest_window, Some(1024));
        assert!(!link.link_up());
        assert!(link.disabled());
        assert!(link.read().is_none());
    }
    #[test]
    fn tuple_and_header_boundaries_refuse_unrelated_or_incomplete_frames() {
        let bytes = frame(0);
        for end in 0..bytes.len() {
            assert_eq!(window(&bytes[..end], 7300), None);
        }
        assert_eq!(window(&bytes, 7301), None);
        for (offset, value) in [
            (12, 0),
            (14, 0x65),
            (14, 0x4f),
            (16, 1),
            (20, 0x20),
            (21, 1),
            (23, 17),
            (26, 11),
            (30, 11),
            (36, 0),
            (46, 0x10),
            (46, 0xf0),
            (47, 0),
            (47, 0x14),
        ] {
            let mut changed = bytes;
            changed[offset] = value;
            assert_eq!(
                window(&changed, 7300),
                None,
                "offset {offset} value {value}"
            );
        }
    }
    #[test]
    fn clock_refusal_is_sticky() {
        let (mut link, observer) = ObservedLink::new(
            Fake {
                now: Cell::new(10),
                fail: false,
                sent: vec![],
            },
            7300,
        );
        link.send(&frame(0)).unwrap();
        link.inner.now.set(9);
        link.send(&frame(0)).unwrap();
        link.inner.now.set(11);
        link.send(&frame(1)).unwrap();
        assert!(observer.snapshot().clock_refused);
    }
}
