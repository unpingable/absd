//! Exact SPT I219-LM admission, before MMIO or PCI configuration writes.
//! Firmware must supply a 128 KiB BAR0 and leave the function in D0.

pub const VENDOR: u16 = 0x8086;
pub const DEVICE: u16 = 0x15b7;
pub const REGISTER_BYTES: u64 = 128 * 1024;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Refusal {
    Identity,
    Class,
    Header,
    MemoryDecode,
    Bar,
    Capabilities,
    PowerState,
    InterruptMode,
}

/// Capability links are untrusted register data: aligned, bounded, no loops.
/// BAR sizing is deliberately absent: writing all ones can affect a live device.
pub fn admit(mut read: impl FnMut(u8) -> u32) -> Result<u64, Refusal> {
    if read(0) != (u32::from(DEVICE) << 16 | u32::from(VENDOR)) {
        return Err(Refusal::Identity);
    }
    if read(8) >> 8 != 0x020000 {
        return Err(Refusal::Class);
    }
    if (read(0x0c) >> 16) & 0x7f != 0 {
        return Err(Refusal::Header);
    }
    let command_status = read(4);
    if command_status & 2 == 0 {
        return Err(Refusal::MemoryDecode);
    }
    let bar = read(0x10);
    // This exact PCH function has a 32-bit non-prefetchable 128 KiB BAR.
    if bar == 0 || bar == u32::MAX || bar & 0x1ffff != 0 {
        return Err(Refusal::Bar);
    }
    if command_status & (1 << 20) == 0 {
        return Err(Refusal::Capabilities);
    }
    let mut offset = (read(0x34) & 0xff) as u8;
    let mut seen = 0u64;
    let mut pm = false;
    while offset != 0 {
        if offset < 0x40 || offset & 3 != 0 {
            return Err(Refusal::Capabilities);
        }
        let bit = 1u64 << (offset / 4);
        if seen & bit != 0 {
            return Err(Refusal::Capabilities);
        }
        seen |= bit;
        let header = read(offset);
        match header as u8 {
            1 => {
                if pm || offset > 0xf8 {
                    return Err(Refusal::Capabilities);
                }
                pm = true;
                if read(offset + 4) & 3 != 0 {
                    return Err(Refusal::PowerState);
                }
            }
            5 if header & (1 << 16) != 0 => return Err(Refusal::InterruptMode),
            0x11 if header & (1 << 31) != 0 => return Err(Refusal::InterruptMode),
            0xff => return Err(Refusal::Capabilities),
            _ => {}
        }
        offset = (header >> 8) as u8;
    }
    if !pm {
        return Err(Refusal::Capabilities);
    }
    Ok(u64::from(bar))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn config() -> [u32; 64] {
        let mut c = [0; 64];
        c[0] = 0x15b78086;
        c[1] = (1 << 20) | 2;
        c[2] = 0x02000031;
        c[4] = 0xf7000000;
        c[0x34 / 4] = 0xc8;
        c[0xc8 / 4] = 1;
        c
    }

    fn check(c: [u32; 64]) -> Result<u64, Refusal> {
        admit(|offset| c[usize::from(offset / 4)])
    }

    #[test]
    fn exact_identity_and_resource_requirements() {
        assert_eq!(check(config()), Ok(0xf7000000));
        for id in [0xffffffff, 0x100e8086, 0x15b88086, 0x15b71234] {
            let mut c = config();
            c[0] = id;
            assert_eq!(check(c), Err(Refusal::Identity));
        }
        for bar in [0, u32::MAX, 0xf7000001, 0xf7000004, 0xf7000008, 0xf7001000] {
            let mut c = config();
            c[4] = bar;
            assert_eq!(check(c), Err(Refusal::Bar));
        }
        let mut c = config();
        c[2] = 0x01080000;
        assert_eq!(check(c), Err(Refusal::Class));
        let mut c = config();
        c[3] = 1 << 16;
        assert_eq!(check(c), Err(Refusal::Header));
        let mut c = config();
        c[1] &= !2;
        assert_eq!(check(c), Err(Refusal::MemoryDecode));
    }

    #[test]
    fn firmware_power_interrupt_and_capability_refusals() {
        for state in 1..=3 {
            let mut c = config();
            c[0xcc / 4] = state;
            assert_eq!(check(c), Err(Refusal::PowerState));
        }
        for header in [0x00010005, 0x80000011] {
            let mut c = config();
            c[0xc8 / 4] |= 0xd0 << 8;
            c[0xd0 / 4] = header;
            assert_eq!(check(c), Err(Refusal::InterruptMode));
        }
        for pointer in [0, 0x3c, 0xc9, 0xff] {
            let mut c = config();
            c[0x34 / 4] = pointer;
            assert_eq!(check(c), Err(Refusal::Capabilities));
        }
        let mut c = config();
        c[0xc8 / 4] |= 0xc8 << 8;
        assert_eq!(check(c), Err(Refusal::Capabilities));
        let mut c = config();
        c[1] &= !(1 << 20);
        assert_eq!(check(c), Err(Refusal::Capabilities));
        let mut c = config();
        c[0xc8 / 4] = 0x0000d001;
        c[0xd0 / 4] = 1;
        assert_eq!(check(c), Err(Refusal::Capabilities));
    }
}
