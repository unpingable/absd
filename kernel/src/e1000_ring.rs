//! The e1000 (82540EM) descriptor and receive destination rules, kept apart
//! from the MMIO driver (`src/e1000.rs`) so they run under `cargo test` on
//! the host.
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

/// The fixed Ethernet receive policy. The hardware multicast hash cannot
/// distinguish the solicited-node prefix from unrelated multicast addresses,
/// so this check runs before a received frame reaches the NIC holder.
/// Protocol validation and configured-address membership remain in userspace.
pub fn accept_rx_destination(destination: [u8; 6], mac: [u8; 6]) -> bool {
    destination == mac
        || destination == [0xff; 6]
        || destination == [0x33, 0x33, 0, 0, 0, 1]
        || destination[..3] == [0x33, 0x33, 0xff]
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

/// What one send's transmit bound decided (kernel record
/// docs/service-lifecycle-20261008/DEGRADED-OPERATION-LIVENESS.md §10).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TxOutcome {
    /// The device reported the posted descriptor done.
    Sent,
    /// A link outcome: carrier was absent at some point of the bound and the
    /// frame was not reported done. Nothing is disabled; a descriptor may
    /// still be device-owned.
    NoCarrier,
    /// A device outcome: a whole bound ran with carrier present and expired.
    /// The caller disables the NIC; a held descriptor stays abandoned, never
    /// reused.
    DeviceFailed,
}

/// The transmit counters `nic_info` reports, moved only by `TxSlots`.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct TxCounters {
    /// Descriptors whose done bit was observed, each counted once.
    pub frames: u64,
    /// Transmit bounds that expired: one per held episode, one per device
    /// outcome; refusals while held count nothing.
    pub errors: u64,
}

/// What `TxSlots` needs from the device: MMIO in `src/e1000.rs`, a model
/// under `cargo test`.
pub trait TxPort {
    /// `STATUS.LU`, read live.
    fn link_up(&mut self) -> bool;
    /// Descriptor `index`'s done bit, read once.
    fn done(&mut self, index: usize) -> bool;
    /// Writes descriptor `index` for a `wire`-byte frame already in its
    /// buffer and moves the tail to `tail`.
    fn post(&mut self, index: usize, wire: usize, tail: usize);
    /// Polls descriptor `index`'s done bit under one transmit bound: true
    /// once it is seen, false when the bound expired first. Sets
    /// `carrier_lost` if `STATUS.LU` read clear at any poll of the bound
    /// (never clears it).
    fn wait_done(&mut self, index: usize, carrier_lost: &mut bool) -> bool;
}

/// Transmit ring ownership. Sends are synchronous, so at most one
/// descriptor is device-owned without its done bit observed: the one just
/// posted, or `held`, whose bound expired after carrier was seen absent. A
/// held descriptor and its buffer are the device's until its done bit is
/// seen; nothing is posted while one is held, so none is ever rewritten.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct TxSlots {
    next: usize,
    held: Option<usize>,
}

impl TxSlots {
    pub const fn new() -> Self {
        Self {
            next: 0,
            held: None,
        }
    }

    /// The descriptor held since a bound expired without carrier.
    pub const fn held(&self) -> Option<usize> {
        self.held
    }

    /// Counts a held descriptor whose done bit has appeared, once, and
    /// frees it. Reads one done bit; writes nothing to the device.
    pub fn reap(&mut self, port: &mut impl TxPort, counters: &mut TxCounters) {
        if let Some(index) = self.held
            && port.done(index)
        {
            counters.frames += 1;
            self.held = None;
        }
    }

    /// Before a frame is copied in: the descriptor to fill, or the outcome
    /// that ends this send with nothing posted. Held without carrier:
    /// `NoCarrier` at once, no wait, no counter. Held with carrier back:
    /// one fresh bound for the held descriptor first, judged as in
    /// `transmit` (carrier seen clear during it holds on; a whole bound with
    /// carrier is `DeviceFailed`).
    pub fn before_post(
        &mut self,
        port: &mut impl TxPort,
        counters: &mut TxCounters,
    ) -> Result<usize, TxOutcome> {
        self.reap(port, counters);
        if let Some(index) = self.held {
            if !port.link_up() {
                return Err(TxOutcome::NoCarrier);
            }
            let mut carrier_lost = false;
            if port.wait_done(index, &mut carrier_lost) {
                counters.frames += 1;
                self.held = None;
            } else if carrier_lost || !port.link_up() {
                return Err(TxOutcome::NoCarrier);
            } else {
                counters.errors += 1;
                return Err(TxOutcome::DeviceFailed);
            }
        }
        Ok(self.next)
    }

    /// Posts `index` (from `before_post`, its buffer filled) and waits one
    /// bound. On expiry the bound is a link outcome if `STATUS.LU` read
    /// clear at post, at any poll, or at expiry: the descriptor is held
    /// (`NoCarrier`). Otherwise the whole bound had carrier: `DeviceFailed`.
    /// An `index` that is not the free slot posts nothing, waits nothing,
    /// counts nothing, and is `DeviceFailed`.
    pub fn transmit(
        &mut self,
        port: &mut impl TxPort,
        index: usize,
        wire: usize,
        counters: &mut TxCounters,
    ) -> TxOutcome {
        // Not the free slot `before_post` handed out: a caller bug, but one
        // that must not panic the kernel. Nothing is posted (I3); the device
        // outcome makes the caller disable the NIC.
        if self.held.is_some() || index != self.next {
            return TxOutcome::DeviceFailed;
        }
        let tail = next(index, TX_DESCRIPTORS);
        self.next = tail;
        let mut carrier_lost = !port.link_up();
        port.post(index, wire, tail);
        if port.wait_done(index, &mut carrier_lost) {
            counters.frames += 1;
            return TxOutcome::Sent;
        }
        counters.errors += 1;
        if carrier_lost || !port.link_up() {
            self.held = Some(index);
            TxOutcome::NoCarrier
        } else {
            TxOutcome::DeviceFailed
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn receive_destination_preserves_station_and_broadcast() {
        let mac = [0x52, 0x54, 0, 0x12, 0x34, 0x56];
        assert!(accept_rx_destination(mac, mac));
        assert!(accept_rx_destination([0xff; 6], mac));
        assert!(!accept_rx_destination(
            [0x52, 0x54, 0, 0x12, 0x34, 0x57],
            mac
        ));
        assert!(!accept_rx_destination([0; 6], mac));
    }

    #[test]
    fn receive_destination_accepts_all_nodes_and_solicited_node_suffixes() {
        let mac = [0x52, 0x54, 0, 0x12, 0x34, 0x56];
        assert!(accept_rx_destination([0x33, 0x33, 0, 0, 0, 1], mac));
        // Exercise all final 16 bits and each value of the remaining suffix
        // byte independently, including groups unrelated to the station MAC.
        for suffix in 0..=u16::MAX {
            let [a, b] = suffix.to_be_bytes();
            assert!(accept_rx_destination([0x33, 0x33, 0xff, 0x81, a, b], mac));
        }
        for suffix in 0..=u8::MAX {
            assert!(accept_rx_destination(
                [0x33, 0x33, 0xff, suffix, 0x12, 0x34],
                mac
            ));
        }
    }

    #[test]
    fn receive_destination_refuses_other_multicast_and_prefix_near_misses() {
        let mac = [0x52, 0x54, 0, 0x12, 0x34, 0x56];
        for destination in [
            [0x01, 0, 0x5e, 0, 0, 1],    // IPv4 multicast.
            [0x33, 0x33, 0, 0, 0, 2],    // IPv6 all routers.
            [0x33, 0x33, 0, 0, 0, 0xfb], // IPv6 multicast DNS.
            [0x33, 0x33, 0xfe, 0x12, 0x34, 0x56],
            [0x33, 0x32, 0xff, 0x12, 0x34, 0x56],
            [0x32, 0x33, 0xff, 0x12, 0x34, 0x56],
            [0x33, 0x33, 0, 0, 1, 1],
        ] {
            assert!(!accept_rx_destination(destination, mac), "{destination:?}");
        }
    }

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

    /// A model device. A posted descriptor completes inside its bound when
    /// `completes`; `link` is carrier; `drop_link_in_wait` takes carrier
    /// away while a bound runs and `raise_link_in_wait` brings it back
    /// (both: a flap, LU clear only between two polls);
    /// `drop_link_at_expiry` takes carrier away after the bound's last poll.
    /// Every poll inside a bound reports a clear `link` through
    /// `carrier_lost` (ruling R2). Any post over a device-owned descriptor
    /// is recorded (I3).
    #[derive(Default)]
    struct Model {
        link: bool,
        completes: bool,
        drop_link_in_wait: bool,
        raise_link_in_wait: bool,
        drop_link_at_expiry: bool,
        dd: [bool; TX_DESCRIPTORS],
        owned: [bool; TX_DESCRIPTORS],
        posted: u64,
        waits: u64,
        overwrote_owned: bool,
    }

    impl Model {
        fn up() -> Self {
            Self {
                link: true,
                completes: true,
                ..Self::default()
            }
        }

        /// The device completes `index` after its bound expired.
        fn complete_late(&mut self, index: usize) {
            assert!(
                self.owned[index],
                "only a device-owned descriptor completes"
            );
            self.owned[index] = false;
            self.dd[index] = true;
        }
    }

    impl TxPort for Model {
        fn link_up(&mut self) -> bool {
            self.link
        }

        fn done(&mut self, index: usize) -> bool {
            self.dd[index]
        }

        fn post(&mut self, index: usize, _wire: usize, _tail: usize) {
            self.overwrote_owned |= self.owned[index];
            self.owned[index] = true;
            self.dd[index] = false;
            self.posted += 1;
        }

        fn wait_done(&mut self, index: usize, carrier_lost: &mut bool) -> bool {
            self.waits += 1;
            *carrier_lost |= !self.link;
            if self.drop_link_in_wait {
                self.link = false;
                *carrier_lost |= !self.link;
            }
            if self.raise_link_in_wait {
                self.link = true;
                *carrier_lost |= !self.link;
            }
            if self.drop_link_at_expiry {
                self.link = false;
            }
            if self.completes && self.owned[index] {
                self.complete_late(index);
            }
            self.dd[index]
        }
    }

    fn send(slots: &mut TxSlots, model: &mut Model, counters: &mut TxCounters) -> TxOutcome {
        match slots.before_post(model, counters) {
            Err(outcome) => outcome,
            Ok(index) => slots.transmit(model, index, 60, counters),
        }
    }

    /// I1 and I3: every posted descriptor is counted done, held, or
    /// abandoned by a device outcome; none was rewritten while owned.
    fn ledger(slots: &TxSlots, model: &Model, counters: &TxCounters, abandoned: u64) {
        assert_eq!(
            model.posted,
            counters.frames + u64::from(slots.held().is_some()) + abandoned,
            "I1: posted = frames + held + abandoned"
        );
        assert!(
            !model.overwrote_owned,
            "I3: a device-owned descriptor was rewritten"
        );
    }

    /// One send whose bound expires without carrier: descriptor 0 held.
    fn one_held() -> (TxSlots, Model, TxCounters) {
        let (mut slots, mut model, mut counters) =
            (TxSlots::new(), Model::default(), TxCounters::default());
        assert_eq!(
            send(&mut slots, &mut model, &mut counters),
            TxOutcome::NoCarrier
        );
        (slots, model, counters)
    }

    #[test]
    fn carrier_present_completion_counts_once_and_never_holds() {
        let (mut slots, mut model, mut counters) =
            (TxSlots::new(), Model::up(), TxCounters::default());
        for _ in 0..40 {
            assert_eq!(send(&mut slots, &mut model, &mut counters), TxOutcome::Sent);
        }
        assert_eq!(
            counters,
            TxCounters {
                frames: 40,
                errors: 0
            }
        );
        assert_eq!(slots.held(), None);
        ledger(&slots, &model, &counters, 0);
    }

    #[test]
    fn bound_expiry_without_carrier_is_a_link_outcome_that_holds_the_descriptor() {
        let (slots, model, counters) = one_held();
        assert_eq!(slots.held(), Some(0));
        assert!(model.owned[0], "the held descriptor stays device-owned");
        assert_eq!(
            counters,
            TxCounters {
                frames: 0,
                errors: 1
            }
        );
        ledger(&slots, &model, &counters, 0);
    }

    #[test]
    fn sends_while_held_without_carrier_refuse_at_once_and_count_nothing() {
        let (mut slots, mut model, mut counters) = one_held();
        let waits = model.waits;
        for _ in 0..20 {
            assert_eq!(
                send(&mut slots, &mut model, &mut counters),
                TxOutcome::NoCarrier
            );
        }
        assert_eq!(model.waits, waits, "I6: a refusal never waits");
        assert_eq!(model.posted, 1, "I6: a refusal posts nothing");
        assert_eq!(
            counters,
            TxCounters {
                frames: 0,
                errors: 1
            },
            "I4: one error per held episode"
        );
        ledger(&slots, &model, &counters, 0);
    }

    #[test]
    fn a_late_done_bit_is_counted_once_by_reap_then_posting_resumes() {
        let (mut slots, mut model, mut counters) = one_held();
        model.complete_late(0);
        slots.reap(&mut model, &mut counters);
        slots.reap(&mut model, &mut counters);
        assert_eq!(
            (slots.held(), counters),
            (
                None,
                TxCounters {
                    frames: 1,
                    errors: 1
                }
            )
        );
        model.link = true;
        model.completes = true;
        assert_eq!(send(&mut slots, &mut model, &mut counters), TxOutcome::Sent);
        assert_eq!(
            counters,
            TxCounters {
                frames: 2,
                errors: 1
            }
        );
        ledger(&slots, &model, &counters, 0);
    }

    #[test]
    fn carrier_back_waits_one_bound_for_the_held_descriptor_then_posts() {
        let (mut slots, mut model, mut counters) = one_held();
        model.link = true;
        model.completes = true;
        let waits = model.waits;
        assert_eq!(send(&mut slots, &mut model, &mut counters), TxOutcome::Sent);
        assert_eq!(
            model.waits,
            waits + 2,
            "one bound for the held descriptor, one for the new frame"
        );
        assert_eq!(
            counters,
            TxCounters {
                frames: 2,
                errors: 1
            }
        );
        ledger(&slots, &model, &counters, 0);
    }

    #[test]
    fn carrier_back_without_completion_is_a_device_failure() {
        let (mut slots, mut model, mut counters) = one_held();
        model.link = true;
        assert_eq!(
            send(&mut slots, &mut model, &mut counters),
            TxOutcome::DeviceFailed
        );
        assert_eq!(model.posted, 1, "nothing new is posted");
        assert_eq!(
            slots.held(),
            Some(0),
            "the held descriptor is abandoned in place, never reused"
        );
        assert_eq!(
            counters,
            TxCounters {
                frames: 0,
                errors: 2
            }
        );
        ledger(&slots, &model, &counters, 0);
    }

    #[test]
    fn carrier_lost_again_during_the_held_bound_stays_a_link_outcome() {
        let (mut slots, mut model, mut counters) = one_held();
        model.link = true;
        model.drop_link_in_wait = true;
        assert_eq!(
            send(&mut slots, &mut model, &mut counters),
            TxOutcome::NoCarrier
        );
        assert_eq!(
            (slots.held(), counters),
            (
                Some(0),
                TxCounters {
                    frames: 0,
                    errors: 1
                }
            )
        );
        ledger(&slots, &model, &counters, 0);
    }

    #[test]
    fn bound_expiry_with_carrier_is_a_device_failure() {
        let (mut slots, mut counters) = (TxSlots::new(), TxCounters::default());
        let mut model = Model {
            link: true,
            ..Model::default()
        };
        assert_eq!(
            send(&mut slots, &mut model, &mut counters),
            TxOutcome::DeviceFailed
        );
        assert_eq!(
            (slots.held(), counters),
            (
                None,
                TxCounters {
                    frames: 0,
                    errors: 1
                }
            )
        );
        ledger(&slots, &model, &counters, 1);
    }

    /// Ruling R2: a bound during which carrier was ever seen clear is not a
    /// full bound with carrier, so its expiry holds even with `LU` set at
    /// expiry; the held descriptor then gets R1's fresh bound.
    #[test]
    fn carrier_returning_mid_bound_is_still_a_link_outcome() {
        let (mut slots, mut counters) = (TxSlots::new(), TxCounters::default());
        let mut model = Model {
            raise_link_in_wait: true,
            ..Model::default()
        };
        assert_eq!(
            send(&mut slots, &mut model, &mut counters),
            TxOutcome::NoCarrier
        );
        assert!(model.link, "carrier is back by the expiry");
        assert_eq!(slots.held(), Some(0), "held, not disabled");
        assert_eq!(
            counters,
            TxCounters {
                frames: 0,
                errors: 1
            }
        );
        ledger(&slots, &model, &counters, 0);
        model.raise_link_in_wait = false;
        model.completes = true;
        let waits = model.waits;
        assert_eq!(send(&mut slots, &mut model, &mut counters), TxOutcome::Sent);
        assert_eq!(
            model.waits,
            waits + 2,
            "one fresh bound for the held descriptor, one for the new frame"
        );
        assert_eq!(
            (slots.held(), counters),
            (
                None,
                TxCounters {
                    frames: 2,
                    errors: 1
                }
            )
        );
        ledger(&slots, &model, &counters, 0);
    }

    /// Review M1: carrier returns (R1's fresh bound is granted), then flaps
    /// during that bound and is back by its expiry with no done bit: still
    /// a link outcome (R2), held again, no second error (I4).
    #[test]
    fn a_carrier_flap_during_the_held_bound_stays_a_link_outcome() {
        let (mut slots, mut model, mut counters) = one_held();
        model.link = true;
        model.drop_link_in_wait = true;
        model.raise_link_in_wait = true;
        let waits = model.waits;
        assert_eq!(
            send(&mut slots, &mut model, &mut counters),
            TxOutcome::NoCarrier
        );
        assert_eq!(model.waits, waits + 1, "the fresh bound was granted");
        assert!(model.link, "carrier is back by the expiry");
        assert_eq!(model.posted, 1, "nothing new is posted");
        assert_eq!(
            (slots.held(), counters),
            (
                Some(0),
                TxCounters {
                    frames: 0,
                    errors: 1
                }
            )
        );
        ledger(&slots, &model, &counters, 0);
    }

    /// Review M1: carrier present at every poll of a bound but clear when
    /// it expires is a link outcome, both for a new frame and for a held
    /// descriptor's fresh bound.
    #[test]
    fn carrier_clear_only_at_expiry_is_a_link_outcome() {
        let (mut slots, mut counters) = (TxSlots::new(), TxCounters::default());
        let mut model = Model {
            link: true,
            drop_link_at_expiry: true,
            ..Model::default()
        };
        assert_eq!(
            send(&mut slots, &mut model, &mut counters),
            TxOutcome::NoCarrier
        );
        assert_eq!(
            (slots.held(), counters),
            (
                Some(0),
                TxCounters {
                    frames: 0,
                    errors: 1
                }
            )
        );
        model.link = true;
        let waits = model.waits;
        assert_eq!(
            send(&mut slots, &mut model, &mut counters),
            TxOutcome::NoCarrier
        );
        assert_eq!(model.waits, waits + 1, "the fresh bound was granted");
        assert_eq!(
            (slots.held(), counters),
            (
                Some(0),
                TxCounters {
                    frames: 0,
                    errors: 1
                }
            )
        );
        ledger(&slots, &model, &counters, 0);
    }

    /// Review M2: `transmit` without a free slot (held, or not the slot
    /// `before_post` handed out) cannot panic the kernel; it ends the send
    /// as a device outcome with nothing posted, waited, or counted.
    #[test]
    fn transmit_without_a_free_slot_is_a_device_failure_not_a_panic() {
        let (mut slots, mut model, mut counters) = one_held();
        let (posted, waits, before) = (model.posted, model.waits, slots);
        assert_eq!(
            slots.transmit(&mut model, 1, 60, &mut counters),
            TxOutcome::DeviceFailed
        );
        assert_eq!((model.posted, model.waits, slots), (posted, waits, before));
        assert_eq!(
            counters,
            TxCounters {
                frames: 0,
                errors: 1
            }
        );

        let (mut slots, mut model, mut counters) =
            (TxSlots::new(), Model::up(), TxCounters::default());
        assert_eq!(
            slots.transmit(&mut model, 3, 60, &mut counters),
            TxOutcome::DeviceFailed
        );
        assert_eq!(
            (model.posted, model.waits, slots, counters),
            (0, 0, TxSlots::new(), TxCounters::default())
        );
        assert!(!model.overwrote_owned);
    }

    #[test]
    fn a_held_slot_is_never_written_across_ring_wraps() {
        let (mut slots, mut model, mut counters) =
            (TxSlots::new(), Model::up(), TxCounters::default());
        for _ in 0..TX_DESCRIPTORS - 1 {
            assert_eq!(send(&mut slots, &mut model, &mut counters), TxOutcome::Sent);
        }
        model.link = false;
        model.completes = false;
        assert_eq!(
            send(&mut slots, &mut model, &mut counters),
            TxOutcome::NoCarrier
        );
        assert_eq!(slots.held(), Some(TX_DESCRIPTORS - 1));
        for _ in 0..3 * TX_DESCRIPTORS {
            assert_eq!(
                send(&mut slots, &mut model, &mut counters),
                TxOutcome::NoCarrier
            );
        }
        model.complete_late(TX_DESCRIPTORS - 1);
        model.link = true;
        model.completes = true;
        for _ in 0..3 * TX_DESCRIPTORS {
            assert_eq!(send(&mut slots, &mut model, &mut counters), TxOutcome::Sent);
        }
        assert_eq!(
            counters,
            TxCounters {
                frames: 4 * TX_DESCRIPTORS as u64,
                errors: 1
            }
        );
        ledger(&slots, &model, &counters, 0);
    }
}
