//! Console bytes held back while the screen must not be drawn: on real hardware
//! drawing is slow enough that the boot's pre-enable window, with firmware's bus
//! masters uncontained, can be dominated by it. Serial and the digest are not
//! held back, only the mirror to the screen. Full keeps the oldest and counts.

pub struct DeferLog<const N: usize> {
    bytes: [u8; N],
    len: usize,
    dropped: u64,
}

impl<const N: usize> DeferLog<N> {
    pub const EMPTY: Self = DeferLog {
        bytes: [0; N],
        len: 0,
        dropped: 0,
    };

    pub fn push(&mut self, byte: u8) {
        if self.len < N {
            self.bytes[self.len] = byte;
            self.len += 1;
        } else {
            self.dropped += 1;
        }
    }

    pub fn drain(&mut self, mut each: impl FnMut(u8)) {
        for &byte in &self.bytes[..self.len] {
            each(byte);
        }
        self.len = 0;
    }

    pub fn dropped(&self) -> u64 {
        self.dropped
    }
}

#[cfg(test)]
mod tests;
