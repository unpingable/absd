//! The e1000 (82540EM) descriptor rules, kept apart from the MMIO driver
//! (`src/e1000.rs`) so they run under `cargo test` on the host.
//!
//! Everything the device writes is untrusted: a receive descriptor is
//! accepted only as one whole, error-free frame of `NIC_FRAME_MIN..=
//! NIC_FRAME_MAX` bytes, and a head register that names a slot outside its
//! ring means the device (or the driver's picture of it) is wrong, so the
//! NIC is disabled rather than guessed at.

use crate::nic::{NIC_FRAME_MAX, NIC_FRAME_MIN};

/// Receive descriptors. Under TCG a burst from QEMU's user network can
/// arrive between two timer ticks; 32 keeps that from dropping frames.
pub const RX_DESCRIPTORS: usize = 32;
pub const TX_DESCRIPTORS: usize = 16;
/// Every descriptor owns one buffer this large (RCTL.BSIZE = 2048), so no
/// frame the driver accepts (at most 1514 bytes) can span two.
pub const BUFFER_BYTES: usize = 2048;
/// Ethernet's minimum frame without the FCS; shorter sends are zero-padded.
pub const WIRE_MINIMUM: usize = 60;

pub const RX_STATUS_DD: u8 = 1;
pub const RX_STATUS_EOP: u8 = 1 << 1;
pub const TX_STATUS_DD: u8 = 1;
/// End of packet, insert FCS, report status.
pub const TX_COMMAND: u8 = 1 | (1 << 1) | (1 << 3);

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RxRefusal {
    /// DD without EOP: the frame spans descriptors, which this driver never
    /// asks for (long packets are off).
    Fragment,
    /// The device set an error bit (CRC, symbol, sequence, carrier, RX data,
    /// or a checksum it was never asked to check).
    DeviceError(u8),
    /// A done, error-free descriptor whose length is not a frame this ABI
    /// carries (for instance a 1518-byte VLAN-sized frame).
    Length(u16),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RxVerdict {
    /// The device has not finished this descriptor.
    Empty,
    Frame(usize),
    Refused(RxRefusal),
}

/// Judges one receive descriptor from its status, errors, and length words.
pub fn classify_rx(status: u8, errors: u8, length: u16) -> RxVerdict {
    if status & RX_STATUS_DD == 0 {
        return RxVerdict::Empty;
    }
    if status & RX_STATUS_EOP == 0 {
        return RxVerdict::Refused(RxRefusal::Fragment);
    }
    if errors != 0 {
        return RxVerdict::Refused(RxRefusal::DeviceError(errors));
    }
    let bytes = usize::from(length);
    if !(NIC_FRAME_MIN..=NIC_FRAME_MAX).contains(&bytes) {
        return RxVerdict::Refused(RxRefusal::Length(length));
    }
    RxVerdict::Frame(bytes)
}

/// Whether a head register value names a slot of a ring of `entries`.
pub fn head_in_ring(head: u32, entries: usize) -> bool {
    (head as usize) < entries
}

/// The byte count a send puts on the wire, or `None` for a length the ABI
/// refuses before anything reaches the device.
pub fn send_length(length: u64) -> Option<(usize, usize)> {
    let bytes = usize::try_from(length).ok()?;
    if !(NIC_FRAME_MIN..=NIC_FRAME_MAX).contains(&bytes) {
        return None;
    }
    Some((bytes, bytes.max(WIRE_MINIMUM)))
}

pub const fn next(index: usize, entries: usize) -> usize {
    (index + 1) % entries
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_whole_error_free_frames_in_range_are_accepted() {
        let done = RX_STATUS_DD | RX_STATUS_EOP;
        assert_eq!(classify_rx(0, 0, 60), RxVerdict::Empty);
        assert_eq!(classify_rx(RX_STATUS_EOP, 0, 60), RxVerdict::Empty);
        assert_eq!(classify_rx(done, 0, 14), RxVerdict::Frame(14));
        assert_eq!(classify_rx(done, 0, 60), RxVerdict::Frame(60));
        assert_eq!(classify_rx(done, 0, 1514), RxVerdict::Frame(1514));
        assert_eq!(
            classify_rx(done, 0, 1515),
            RxVerdict::Refused(RxRefusal::Length(1515))
        );
        assert_eq!(
            classify_rx(done, 0, 1518),
            RxVerdict::Refused(RxRefusal::Length(1518))
        );
        assert_eq!(
            classify_rx(done, 0, 13),
            RxVerdict::Refused(RxRefusal::Length(13))
        );
        assert_eq!(
            classify_rx(done, 0, 0),
            RxVerdict::Refused(RxRefusal::Length(0))
        );
        assert_eq!(
            classify_rx(done, 0, u16::MAX),
            RxVerdict::Refused(RxRefusal::Length(u16::MAX))
        );
        assert_eq!(
            classify_rx(RX_STATUS_DD, 0, 60),
            RxVerdict::Refused(RxRefusal::Fragment)
        );
        for bit in 0..8 {
            assert_eq!(
                classify_rx(done, 1 << bit, 60),
                RxVerdict::Refused(RxRefusal::DeviceError(1 << bit))
            );
        }
    }

    #[test]
    fn heads_outside_the_ring_are_refused() {
        assert!(head_in_ring(0, RX_DESCRIPTORS));
        assert!(head_in_ring(31, RX_DESCRIPTORS));
        assert!(!head_in_ring(32, RX_DESCRIPTORS));
        assert!(!head_in_ring(u32::MAX, RX_DESCRIPTORS));
        assert!(head_in_ring(15, TX_DESCRIPTORS));
        assert!(!head_in_ring(16, TX_DESCRIPTORS));
    }

    #[test]
    fn send_lengths_are_bounded_and_padded() {
        assert_eq!(send_length(13), None);
        assert_eq!(send_length(0), None);
        assert_eq!(send_length(1515), None);
        assert_eq!(send_length(u64::MAX), None);
        assert_eq!(send_length(14), Some((14, 60)));
        assert_eq!(send_length(42), Some((42, 60)));
        assert_eq!(send_length(60), Some((60, 60)));
        assert_eq!(send_length(1514), Some((1514, 1514)));
        const { assert!(NIC_FRAME_MAX <= BUFFER_BYTES) };
    }

    #[test]
    fn indexes_wrap_inside_the_ring() {
        assert_eq!(next(0, 16), 1);
        assert_eq!(next(15, 16), 0);
        assert_eq!(next(31, RX_DESCRIPTORS), 0);
    }
}
