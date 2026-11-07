//! Read-only validation of the modern VirtIO Sound PCI capability layout.
//! Reference: VirtIO 1.2 section 4.1.4. No BAR sizing or MMIO occurs here.

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    Chain,
    Truncated,
    Bounds,
    Missing,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Bar {
    pub base: u64,
    pub size: u64,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Region {
    pub address: u64,
    pub length: u32,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Capabilities {
    pub common: Region,
    pub notify: Region,
    pub isr: Region,
    pub device: Region,
    pub multiplier: u32,
}
fn le32(c: &[u8; 256], p: usize) -> u32 {
    u32::from_le_bytes(c[p..p + 4].try_into().unwrap())
}
impl Capabilities {
    /// `bars` contains only assigned memory BARs, sized while decoding is off.
    /// High halves of 64-bit BARs and I/O BARs must be represented as None.
    pub fn parse(c: &[u8; 256], bars: [Option<Bar>; 6]) -> Result<Self, Error> {
        if c[6] & 0x10 == 0 {
            return Err(Error::Missing);
        }
        let mut p = c[0x34] as usize;
        let mut visited = [false; 64];
        let mut regions = [None; 4];
        let mut multiplier = 0;
        while p != 0 {
            if !(0x40..=0xfc).contains(&p) || !p.is_multiple_of(4) || visited[p / 4] {
                return Err(Error::Chain);
            }
            visited[p / 4] = true;
            let next = c[p + 1] as usize;
            if c[p] == 9 {
                let len = c[p + 2] as usize;
                if len < 4 || p + len > 256 {
                    return Err(Error::Truncated);
                }
                let kind = c[p + 3];
                if (1..=4).contains(&kind) {
                    let min = if kind == 2 { 20 } else { 16 };
                    if len < min {
                        return Err(Error::Truncated);
                    }
                    let bar = c[p + 4] as usize;
                    if bar < 6
                        && let Some(b) = bars[bar]
                    {
                        let slot = (kind - 1) as usize;
                        if regions[slot].is_none() {
                            let offset = le32(c, p + 8) as u64;
                            let length = le32(c, p + 12);
                            let (required, align) = match kind {
                                1 => (56, 4),
                                2 => (2, 2),
                                3 => (1, 1),
                                _ => (12, 4),
                            };
                            if length < required
                                || !offset.is_multiple_of(align)
                                || offset + length as u64 > b.size
                                || b.base.checked_add(b.size).is_none()
                                || !b.base.is_multiple_of(align)
                            {
                                return Err(Error::Bounds);
                            }
                            regions[slot] = Some(Region {
                                address: b.base + offset,
                                length,
                            });
                            if kind == 2 {
                                multiplier = le32(c, p + 16);
                            }
                        }
                    }
                }
            }
            p = next;
        }
        Ok(Self {
            common: regions[0].ok_or(Error::Missing)?,
            notify: regions[1].ok_or(Error::Missing)?,
            isr: regions[2].ok_or(Error::Missing)?,
            device: regions[3].ok_or(Error::Missing)?,
            multiplier,
        })
    }
    /// Byte offset is checked in a wide type before a 16-bit MMIO notification.
    pub fn notification(&self, queue_offset: u16) -> Result<u64, Error> {
        let offset = queue_offset as u64 * self.multiplier as u64;
        if !offset.is_multiple_of(2) || offset + 2 > self.notify.length as u64 {
            return Err(Error::Bounds);
        }
        self.notify.address.checked_add(offset).ok_or(Error::Bounds)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn fixture() -> ([u8; 256], [Option<Bar>; 6]) {
        let mut c = [0u8; 256];
        c[6] = 0x10;
        c[0x34] = 0x40;
        for (p, next, kind, offset, len) in [
            (0x40, 0x50, 1, 0, 56),
            (0x50, 0x68, 2, 256, 64),
            (0x68, 0x78, 3, 512, 1),
            (0x78, 0, 4, 768, 12),
        ] {
            c[p] = 9;
            c[p + 1] = next;
            c[p + 2] = if kind == 2 { 20 } else { 16 };
            c[p + 3] = kind;
            c[p + 8..p + 12].copy_from_slice(&(offset as u32).to_le_bytes());
            c[p + 12..p + 16].copy_from_slice(&(len as u32).to_le_bytes());
        }
        c[0x60..0x64].copy_from_slice(&4u32.to_le_bytes());
        (
            c,
            [
                Some(Bar {
                    base: 0x8000_0000,
                    size: 4096,
                }),
                None,
                None,
                None,
                None,
                None,
            ],
        )
    }
    #[test]
    fn valid_layout_and_notification_bounds() {
        let (c, b) = fixture();
        let caps = Capabilities::parse(&c, b).unwrap();
        assert_eq!(caps.common.address, 0x8000_0000);
        assert_eq!(caps.device.address, 0x8000_0300);
        assert_eq!(caps.notification(15), Ok(0x8000_013c));
        assert_eq!(caps.notification(16), Err(Error::Bounds));
    }
    #[test]
    fn malformed_chain_is_refused() {
        for next in [0x40, 0x41, 0x3c] {
            let (mut c, b) = fixture();
            c[0x41] = next;
            assert_eq!(Capabilities::parse(&c, b), Err(Error::Chain));
        }
        let (mut c, b) = fixture();
        c[0x52] = 16;
        assert_eq!(Capabilities::parse(&c, b), Err(Error::Truncated));
    }
    #[test]
    fn inaccessible_and_short_regions_are_refused() {
        let (c, mut b) = fixture();
        b[0].as_mut().unwrap().size = 770;
        assert_eq!(Capabilities::parse(&c, b), Err(Error::Bounds));
        let (mut c, b) = fixture();
        c[0x4c] = 55;
        assert_eq!(Capabilities::parse(&c, b), Err(Error::Bounds));
        let (mut c, b) = fixture();
        c[0x48] = 1;
        assert_eq!(Capabilities::parse(&c, b), Err(Error::Bounds));
    }
    #[test]
    fn unsupported_bar_or_type_does_not_become_a_region() {
        let (mut c, b) = fixture();
        c[0x44] = 6;
        assert_eq!(Capabilities::parse(&c, b), Err(Error::Missing));
        let (mut c, b) = fixture();
        c[0x43] = 7;
        assert_eq!(Capabilities::parse(&c, b), Err(Error::Missing));
    }
    #[test]
    fn absent_list_and_overflow_are_refused() {
        let (mut c, b) = fixture();
        c[6] = 0;
        assert_eq!(Capabilities::parse(&c, b), Err(Error::Missing));
        let (c, mut b) = fixture();
        b[0].as_mut().unwrap().base = u64::MAX - 3;
        assert_eq!(Capabilities::parse(&c, b), Err(Error::Bounds));
    }
}
