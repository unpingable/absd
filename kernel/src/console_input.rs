//! The bounded byte FIFO shared by physical Console input sources.
//! The runtime owner serializes access on the BSP with interrupts disabled.

/// Two maximum 4095-byte canonical lines plus their terminators. IRQ work
/// remains bounded separately; headroom covers bursts between Console reads.
pub const CAPACITY: usize = 8192;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Source {
    Serial = 0,
    Keyboard = 1,
}

pub struct Input {
    bytes: [u8; CAPACITY],
    head: usize,
    len: usize,
    accepted: [u64; 2],
    dropped: [u64; 2],
    reported: [u64; 2],
    loss_report_tick: Option<u64>,
}

impl Default for Input {
    fn default() -> Self {
        Self::new()
    }
}

impl Input {
    pub const fn new() -> Self {
        Self {
            bytes: [0; CAPACITY],
            head: 0,
            len: 0,
            accepted: [0; 2],
            dropped: [0; 2],
            reported: [0; 2],
            loss_report_tick: None,
        }
    }

    /// Drop the new byte when full; existing data is never displaced.
    pub fn push(&mut self, source: Source, byte: u8) -> bool {
        let index = source as usize;
        if self.len == CAPACITY {
            self.dropped[index] = self.dropped[index].saturating_add(1);
            return false;
        }
        self.bytes[(self.head + self.len) % CAPACITY] = byte;
        self.len += 1;
        self.accepted[index] = self.accepted[index].saturating_add(1);
        true
    }

    pub fn take(&mut self, out: &mut [u8]) -> usize {
        let count = out.len().min(self.len);
        for byte in &mut out[..count] {
            *byte = self.bytes[self.head];
            self.head = (self.head + 1) % CAPACITY;
        }
        self.len -= count;
        count
    }

    pub fn available(&self) -> usize {
        self.len
    }

    pub fn accepted(&self, source: Source) -> u64 {
        self.accepted[source as usize]
    }

    pub fn dropped(&self, source: Source) -> u64 {
        self.dropped[source as usize]
    }

    /// Observe new loss at a Console read boundary, never in an input ISR.
    /// The retained logger never displays input bytes or blocks. Coalesce
    /// changed counters to one attempt per 1000 ticks, retaining a failed
    /// publication for a later read rather than silently marking it reported.
    pub fn report_loss(&mut self, now: u64, log: &crate::kernel_log::Log) -> bool {
        if self.dropped == self.reported
            || self
                .loss_report_tick
                .is_some_and(|last| now.saturating_sub(last) < 1000)
        {
            return false;
        }
        self.loss_report_tick = Some(now);
        struct Message {
            bytes: [u8; 128],
            len: usize,
        }
        impl core::fmt::Write for Message {
            fn write_str(&mut self, text: &str) -> core::fmt::Result {
                if text.len() > self.bytes.len() - self.len {
                    return Err(core::fmt::Error);
                }
                self.bytes[self.len..self.len + text.len()].copy_from_slice(text.as_bytes());
                self.len += text.len();
                Ok(())
            }
        }
        use core::fmt::Write;
        let mut message = Message {
            bytes: [0; 128],
            len: 0,
        };
        // Even two saturated u64 counters fit in this fixed message buffer.
        let _ = write!(
            message,
            "physical Console input loss serial={} keyboard={} capacity={}",
            self.dropped[0], self.dropped[1], CAPACITY
        );
        if log.emit(
            b"console-input",
            4,
            Some(now),
            &message.bytes[..message.len],
            0,
        ) {
            self.reported = self.dropped;
            true
        } else {
            false
        }
    }

    pub fn total_dropped(&self) -> u64 {
        self.dropped[0].saturating_add(self.dropped[1])
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::vec::Vec;

    #[test]
    fn sources_share_enqueue_order_across_wrap() {
        let mut input = Input::new();
        for n in 0..250 {
            assert!(input.push(Source::Serial, n as u8));
        }
        let mut out = [0; 240];
        assert_eq!(input.take(&mut out), 240);
        for (n, &byte) in out.iter().enumerate() {
            assert_eq!(byte, n as u8);
        }
        for &byte in b"keyboard" {
            assert!(input.push(Source::Keyboard, byte));
        }
        for &byte in b"serial" {
            assert!(input.push(Source::Serial, byte));
        }
        let mut out = [0; 256];
        assert_eq!(input.take(&mut out), 24);
        assert_eq!(
            &out[..10],
            &[240, 241, 242, 243, 244, 245, 246, 247, 248, 249]
        );
        assert_eq!(&out[10..24], b"keyboardserial");
        assert_eq!(input.accepted(Source::Serial), 256);
        assert_eq!(input.accepted(Source::Keyboard), 8);
        assert_eq!(input.available(), 0);
    }

    #[test]
    fn overflow_preserves_old_bytes_and_counts_each_source() {
        let mut input = Input::new();
        for n in 0..CAPACITY {
            assert!(input.push(Source::Serial, n as u8));
        }
        assert!(!input.push(Source::Keyboard, b'x'));
        assert!(!input.push(Source::Serial, b'y'));
        assert!(!input.push(Source::Keyboard, b'z'));
        assert_eq!(input.dropped(Source::Keyboard), 2);
        assert_eq!(input.dropped(Source::Serial), 1);
        assert_eq!(input.total_dropped(), 3);
        assert_eq!(input.accepted(Source::Keyboard), 0);
        assert_eq!(input.take(&mut []), 0);
        let mut out = [0; CAPACITY + 1];
        assert_eq!(input.take(&mut out), CAPACITY);
        for (n, &byte) in out[..CAPACITY].iter().enumerate() {
            assert_eq!(byte, n as u8);
        }
        assert!(input.push(Source::Keyboard, b'a'));
        assert_eq!(input.take(&mut out), 1);
        assert_eq!(out[0], b'a');
    }

    #[test]
    fn diagnostics_saturate_without_changing_fifo_behavior() {
        let mut input = Input::new();
        input.accepted = [u64::MAX; 2];
        assert!(input.push(Source::Keyboard, b'a'));
        assert_eq!(input.accepted(Source::Keyboard), u64::MAX);
        for _ in 1..CAPACITY {
            input.push(Source::Serial, b'b');
        }
        input.dropped = [u64::MAX; 2];
        assert!(!input.push(Source::Keyboard, b'c'));
        assert_eq!(input.total_dropped(), u64::MAX);
        assert_eq!(input.available(), CAPACITY);
    }
    // Regression: losing the suffix of a burst below the worker's canonical
    // line limit loses its terminator, leaving an ordinary command unfinished.
    fn through_input_fifo(bytes: &[u8]) {
        let mut input = Input::new();
        let mut drained = Vec::new();
        let mut relay = crate::local_console_router::Relay::new();
        for &byte in bytes {
            assert!(
                input.push(Source::Serial, byte),
                "lost a supported burst byte"
            );
        }
        let mut part = [0; 128];
        while input.available() != 0 {
            let n = input.take(&mut part);
            drained.extend_from_slice(&part[..n]);
            relay.enqueue(&part[..n]);
        }
        assert_eq!(drained, bytes);
        assert_eq!(&relay.pending[..relay.count], bytes);
        assert_eq!(relay.dropped, 0);
        assert_eq!(input.total_dropped(), 0);
    }

    #[test]
    fn live149_exact_393_byte_command_reaches_the_fifo_reader() {
        let bytes = include_bytes!("../user/tests/vectors/console-burst149.input");
        assert_eq!(bytes.len(), 393);
        assert_eq!(bytes.last(), Some(&b'\r'));
        through_input_fifo(bytes);
    }

    #[test]
    fn full_canonical_line_keeps_its_terminator() {
        let mut bytes = vec![b'x'; 4095];
        bytes.push(b'\n');
        through_input_fifo(&bytes);
    }

    #[test]
    fn two_coalesced_maximum_command_lines_keep_every_byte() {
        let mut bytes = Vec::new();
        for value in *b"ab" {
            bytes.extend_from_slice(b"echo ");
            bytes.extend(std::iter::repeat_n(value, 4090));
            bytes.push(b'\r');
        }
        assert_eq!(bytes.len(), 8192);
        through_input_fifo(&bytes);
    }

    #[test]
    fn burst_after_partial_read_wraps_without_reordering_sources() {
        let mut input = Input::new();
        for _ in 0..8000 {
            assert!(input.push(Source::Serial, b's'));
        }
        let mut prefix = [0; 7900];
        assert_eq!(input.take(&mut prefix), 7900);
        assert_eq!(prefix, [b's'; 7900]);
        for _ in 0..2000 {
            assert!(input.push(Source::Keyboard, b'k'));
        }
        let mut remaining = [0; 2100];
        assert_eq!(input.take(&mut remaining), 2100);
        assert_eq!(&remaining[..100], &[b's'; 100]);
        assert_eq!(&remaining[100..], &[b'k'; 2000]);
        assert_eq!(input.total_dropped(), 0);
    }

    #[test]
    fn new_loss_is_retained_without_entered_bytes_and_coalesced() {
        let log = crate::kernel_log::Log::new();
        let mut input = Input::new();
        assert!(!input.report_loss(0, &log));
        for _ in 0..8192 {
            input.push(Source::Serial, b'P');
        }
        assert!(!input.push(Source::Serial, b's'));
        assert!(input.report_loss(0, &log));
        let first = log.read(0).unwrap();
        let record = first.record.unwrap();
        assert_eq!(record.source(), b"console-input");
        assert_eq!(record.severity, 4);
        assert_eq!(record.ticks, Some(0));
        assert!(
            record
                .text()
                .windows(19)
                .any(|w| w == b"serial=1 keyboard=0")
        );
        assert!(!record.text().contains(&b'P'));
        assert!(!input.report_loss(200, &log)); // No new drops, no warning.
        assert!(!input.push(Source::Keyboard, b'k'));
        assert!(!input.push(Source::Keyboard, b'k'));
        assert!(!input.report_loss(999, &log));
        assert!(input.report_loss(1000, &log));
        let second = log.read(first.next).unwrap();
        assert!(
            second
                .record
                .unwrap()
                .text()
                .windows(19)
                .any(|w| w == b"serial=1 keyboard=2")
        );
        assert!(!input.report_loss(2000, &log));
        assert!(log.read(second.next).unwrap().record.is_none());
    }

    #[test]
    fn busy_retention_defers_loss_warning_with_a_bounded_retry() {
        let log = crate::kernel_log::Log::new();
        let mut input = Input::new();
        for _ in 0..8192 {
            input.push(Source::Serial, b'x');
        }
        input.push(Source::Serial, b'y');
        log.test_while_locked(|| assert!(!input.report_loss(5, &log)));
        assert!(!input.report_loss(6, &log));
        assert!(input.report_loss(1005, &log));
        assert_eq!(log.read(0).unwrap().producer_dropped, 1);
        assert!(!input.report_loss(2005, &log));
    }
}
