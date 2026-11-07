//! Bounded PIIX3 bus-master IDE descriptor and completion rules.
//!
//! Intel 82371FB/82371SB datasheet 290550-002, sections 2.7 and 3.5.2.2.

/// Only the primary compatibility channel of the supported PIIX3 function.
pub fn controller(id: u32, class: u32, timing: u32, bar: u32) -> Option<u16> {
    if id != 0x7010_8086
        || class >> 8 != 0x010180
        || timing & 0x8000 == 0
        || bar & 0xf != 1
        || bar & 0xffff_0000 != 0
        || bar & !0xf == 0
    {
        return None;
    }
    Some((bar & !0xf) as u16)
}

/// Emulator-only admission: a virtual CPU and the exact QEMU disk model.
/// Model words are ATA big-endian character pairs, space padded to 40 bytes.
/// This is a supported-configuration limit, not physical hardware detection.
pub fn qemu_disk(virtualized: bool, identity: &[u16; 256]) -> bool {
    let model = b"QEMU HARDDISK                           ";
    let supported = identity[88] & 0x7f;
    let selected = (identity[88] >> 8) & 0x7f;
    virtualized
        && identity[49] & 0x100 != 0
        && identity[53] & 4 != 0
        && selected.count_ones() == 1
        && selected & supported == selected
        && (0..20).all(|i| identity[27 + i] == u16::from_be_bytes([model[2 * i], model[2 * i + 1]]))
}

/// A single EOT PRD: word-aligned, 1..=8 sectors, within one 64 KiB window.
pub fn descriptor(address: u64, bytes: usize) -> Option<[u32; 2]> {
    if bytes == 0
        || bytes > 4096
        || !bytes.is_multiple_of(512)
        || address & 1 != 0
        || address.checked_add(bytes as u64)? > 1u64 << 32
        || (address & 0xffff) + bytes as u64 > 65536
    {
        return None;
    }
    Some([address as u32, 0x8000_0000 | bytes as u32])
}

/// Interrupt alone is insufficient: all requested bytes must have retired.
pub fn complete(bus_master: u8, ata: u8) -> bool {
    bus_master & 7 == 4 && ata & (0x80 | 0x20 | 0x08 | 0x01) == 0
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn admission_is_controller_channel_and_bar_specific() {
        assert_eq!(
            controller(0x70108086, 0x01018000, 0x8000, 0xc001),
            Some(0xc000)
        );
        for (id, class, timing, bar) in [
            (0x71118086, 0x01018000, 0x8000, 0xc001),
            (0x70108086, 0x01018100, 0x8000, 0xc001),
            (0x70108086, 0x01018000, 0, 0xc001),
            (0x70108086, 0x01018000, 0x8000, 0),
            (0x70108086, 0x01018000, 0x8000, 0x10001),
        ] {
            assert_eq!(controller(id, class, timing, bar), None);
        }
    }
    #[test]
    fn physical_or_other_model_keeps_pio() {
        let mut identity = [0u16; 256];
        let model = b"QEMU HARDDISK                           ";
        for i in 0..20 {
            identity[27 + i] = u16::from_be_bytes([model[2 * i], model[2 * i + 1]]);
        }
        identity[49] = 0x100;
        identity[53] = 7;
        identity[88] = 0x203f;
        assert!(qemu_disk(true, &identity));
        assert!(!qemu_disk(false, &identity));
        identity[88] = 0x4001;
        assert!(!qemu_disk(true, &identity));
        identity[88] = 0x203f;
        identity[27] ^= 1;
        assert!(!qemu_disk(true, &identity));
    }
    #[test]
    fn descriptor_boundaries() {
        assert_eq!(descriptor(0xfffff000, 4096), Some([0xfffff000, 0x80001000]));
        for (address, bytes) in [
            (0, 0),
            (0, 513),
            (0, 4608),
            (1, 512),
            (0xff00, 512),
            (0xfffffe00, 1024),
            (1u64 << 32, 512),
            (u64::MAX, 512),
        ] {
            assert_eq!(descriptor(address, bytes), None);
        }
    }
    #[test]
    fn completion_requires_exact_success() {
        assert!(complete(4, 0x40));
        for bm in [0, 1, 2, 3, 5, 6, 7] {
            assert!(!complete(bm, 0x40));
        }
        for status in [0x80, 0x20, 8, 1] {
            assert!(!complete(4, status));
        }
    }
}
