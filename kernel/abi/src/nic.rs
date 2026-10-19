//! The network interface ABI (kernel `docs/NETWORK.md`): whole Ethernet
//! frames on the one probed NIC, through a NIC handle. The read right
//! receives, the write right sends. There are no sockets here; a protocol
//! stack runs in the process that holds the handle.
//!
//! A frame is destination MAC, source MAC, EtherType, payload: no preamble
//! and no frame check sequence (the device appends and strips it).

/// `nic_info(handle, record)`: stores a [`NicInfo`] record
/// ([`NIC_INFO_BYTES`]). Requires the read right.
pub const SYS_NIC_INFO: u64 = 32;
/// `nic_send(handle, frame, length)`: sends one frame of
/// [`NIC_FRAME_MIN`]..=[`NIC_FRAME_MAX`] bytes. A frame shorter than 60 bytes
/// is zero-padded to 60 on the wire. Returns 0 once the device reports the
/// descriptor done; `ERROR_INVALID` for a length out of range (nothing
/// reaches the device); `ERROR_IO` once the NIC is disabled;
/// `ERROR_NO_CARRIER` when the link has no carrier and the frame was not
/// reported done: the NIC stays enabled and the descriptor stays the
/// device's. Later sends are refused the same way, at once, until that held
/// descriptor's done bit is seen or carrier returns. After carrier returns
/// the held descriptor gets one fresh bound, and an expiry with carrier
/// present is a device outcome: the NIC is disabled (`ERROR_IO`), as for any
/// other device that does not complete in time. Requires the write right.
pub const SYS_NIC_SEND: u64 = 33;
/// `nic_receive(handle, buffer, timeout)`: copies the next complete,
/// error-free received frame into [`NIC_FRAME_MAX`] writable bytes at
/// `buffer` and returns its length. `timeout` 0 polls: `ERROR_AGAIN` when
/// no frame is waiting. A positive `timeout` waits at most that many ticks,
/// then `ERROR_TIMEOUT`. There is no unbounded receive. `ERROR_IO` once the
/// NIC is disabled. Requires the read right.
pub const SYS_NIC_RECEIVE: u64 = 34;

/// Destination and source MAC and EtherType.
pub const NIC_FRAME_MIN: usize = 14;
/// A 1500-byte payload plus the header; no VLAN tag, no jumbo frames.
pub const NIC_FRAME_MAX: usize = 1514;
pub const NIC_INFO_BYTES: usize = 64;

/// `NicInfo::flags`: the device reports link up.
pub const NIC_FLAG_LINK_UP: u16 = 1;
/// `NicInfo::flags`: the driver disabled the device after it reported
/// something impossible; every send and receive now fails with `ERROR_IO`.
pub const NIC_FLAG_DISABLED: u16 = 1 << 1;

/// What `nic_info` reports. Counters run from boot.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct NicInfo {
    pub mac: [u8; 6],
    pub flags: u16,
    /// Frames handed to a receiver.
    pub rx_frames: u64,
    /// Received descriptors the driver refused and recycled: not done as
    /// one whole frame, carrying an error bit, or a length outside
    /// `NIC_FRAME_MIN..=NIC_FRAME_MAX`.
    pub rx_refused: u64,
    /// Frames the device reported missing for lack of a free descriptor.
    pub rx_missed: u64,
    /// Descriptors the device reported done, each counted once: a
    /// descriptor held without carrier is counted when its done bit is seen,
    /// even though its sender got `ERROR_NO_CARRIER`.
    pub tx_frames: u64,
    /// Sends refused before the device (length out of range).
    pub tx_refused: u64,
    /// Transmit bounds that expired: once per descriptor held without
    /// carrier, once per expiry with carrier present (which disables the
    /// NIC). Sends refused while a descriptor is held count nothing.
    pub tx_errors: u64,
}

impl NicInfo {
    pub fn to_bytes(self) -> [u8; NIC_INFO_BYTES] {
        let mut bytes = [0u8; NIC_INFO_BYTES];
        bytes[..6].copy_from_slice(&self.mac);
        bytes[6..8].copy_from_slice(&self.flags.to_le_bytes());
        for (index, word) in [
            self.rx_frames,
            self.rx_refused,
            self.rx_missed,
            self.tx_frames,
            self.tx_refused,
            self.tx_errors,
        ]
        .iter()
        .enumerate()
        {
            bytes[8 + index * 8..16 + index * 8].copy_from_slice(&word.to_le_bytes());
        }
        bytes
    }

    pub fn from_bytes(bytes: &[u8; NIC_INFO_BYTES]) -> Self {
        let word = |index: usize| {
            let mut raw = [0u8; 8];
            raw.copy_from_slice(&bytes[8 + index * 8..16 + index * 8]);
            u64::from_le_bytes(raw)
        };
        let mut mac = [0u8; 6];
        mac.copy_from_slice(&bytes[..6]);
        Self {
            mac,
            flags: u16::from_le_bytes([bytes[6], bytes[7]]),
            rx_frames: word(0),
            rx_refused: word(1),
            rx_missed: word(2),
            tx_frames: word(3),
            tx_refused: word(4),
            tx_errors: word(5),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn numbers_follow_the_block_and_clock_calls() {
        assert_eq!([SYS_NIC_INFO, SYS_NIC_SEND, SYS_NIC_RECEIVE], [32, 33, 34]);
        assert_eq!(
            (NIC_FRAME_MIN, NIC_FRAME_MAX, NIC_INFO_BYTES),
            (14, 1514, 64)
        );
    }

    #[test]
    fn info_round_trips() {
        let info = NicInfo {
            mac: [0x52, 0x54, 0, 0x12, 0x34, 0x56],
            flags: NIC_FLAG_LINK_UP,
            rx_frames: 1,
            rx_refused: 2,
            rx_missed: 3,
            tx_frames: 4,
            tx_refused: 5,
            tx_errors: 6,
        };
        assert_eq!(NicInfo::from_bytes(&info.to_bytes()), info);
        assert_eq!(&info.to_bytes()[8..16], &1u64.to_le_bytes());
        assert_eq!(&info.to_bytes()[48..56], &6u64.to_le_bytes());
        assert_eq!(&info.to_bytes()[56..], &[0u8; 8]);
    }
}
