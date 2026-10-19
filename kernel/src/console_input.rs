//! The bounded byte FIFO shared by physical Console input sources.
//! The runtime owner serializes access on the BSP with interrupts disabled.

pub const CAPACITY: usize = 256;

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

    pub fn total_dropped(&self) -> u64 {
        self.dropped[0].saturating_add(self.dropped[1])
    }
}

#[cfg(test)]
mod tests {
    use super::*;

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
}
