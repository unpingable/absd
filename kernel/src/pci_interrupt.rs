//! Read-only interrupt discovery for the native xHCI controller lane.
//!
//! This is the conventional 256-byte PCI configuration space of a type-0
//! function, not PCIe extended capabilities or xHCI MMIO capabilities.
//! Discover the entire list before returning a usable result. No register
//! writes, mappings, allocations, interrupt delivery or ownership changes
//! happen here. The caller must separately acquire the device and validate
//! its BARs before configuring either interrupt transport.

const CAP_MSI: u8 = 0x05;
const CAP_MSIX: u8 = 0x11;
const CONFIG_BYTES: u16 = 256;

/// Implementations must read the selected function at an aligned offset.
pub trait ConfigSpace {
    fn read32(&mut self, offset: u8) -> u32;
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Error {
    Absent,
    HeaderType(u8),
    Pointer(u8),
    Cycle(u8),
    Overlap(u8),
    Truncated(u8),
    Duplicate(u8),
    BarIndex(u8),
    MissingMemoryBar(u8),
    BarBounds(u8),
    MsixOverlap,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Msi {
    pub capability: u8,
    pub enabled: bool,
    pub address64: bool,
    pub per_vector_mask: bool,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct BarRegion {
    pub bar: u8,
    pub offset: u64,
    pub bytes: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Msix {
    pub capability: u8,
    pub enabled: bool,
    pub function_masked: bool,
    pub vectors: u16,
    pub table: BarRegion,
    pub pending: BarRegion,
}

impl Msix {
    /// Check the complete table and pending-bit array, even when only one
    /// vector will be used. Each entry is the sized length of an assigned
    /// memory BAR; I/O BARs, unassigned BARs and the upper half of a 64-bit
    /// BAR must be None. This does not map or claim those regions.
    pub fn validate_regions(&self, memory_bar_bytes: [Option<u64>; 6]) -> Result<(), Error> {
        for region in [self.table, self.pending] {
            let bytes = memory_bar_bytes
                .get(usize::from(region.bar))
                .ok_or(Error::BarIndex(region.bar))?
                .ok_or(Error::MissingMemoryBar(region.bar))?;
            if region
                .offset
                .checked_add(region.bytes)
                .is_none_or(|end| end > bytes)
            {
                return Err(Error::BarBounds(region.bar));
            }
        }
        // The additions were checked above.
        if self.table.bar == self.pending.bar
            && self.table.offset < self.pending.offset + self.pending.bytes
            && self.pending.offset < self.table.offset + self.table.bytes
        {
            return Err(Error::MsixOverlap);
        }
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct Capabilities {
    pub msi: Option<Msi>,
    pub msix: Option<Msix>,
}

fn region(register: u32, bytes: u64) -> Result<BarRegion, Error> {
    let bar = (register & 7) as u8;
    if bar >= 6 {
        return Err(Error::BarIndex(bar));
    }
    Ok(BarRegion {
        bar,
        offset: u64::from(register & !7),
        bytes,
    })
}

/// Inspect every linked capability, including entries after MSI/MSI-X.
/// Each of the 48 possible aligned capability headers can be read at most
/// once. A bitmap also prevents a header from naming a word inside a known
/// MSI/MSI-X capability. Unknown capabilities reserve their header only:
/// this function does not claim to know their register layouts.
pub fn discover(config: &mut impl ConfigSpace) -> Result<Capabilities, Error> {
    if config.read32(0) as u16 == 0xffff {
        return Err(Error::Absent);
    }
    let header = ((config.read32(0x0c) >> 16) as u8) & 0x7f;
    if header != 0 {
        return Err(Error::HeaderType(header));
    }
    let mut result = Capabilities::default();
    if config.read32(4) & (1 << 20) == 0 {
        return Ok(result);
    }
    let mut at = config.read32(0x34) as u8;
    let mut visited = 0u64;
    let mut occupied = 0u64;
    while at != 0 {
        if at < 0x40 || at & 3 != 0 {
            return Err(Error::Pointer(at));
        }
        let bit = 1u64 << (at / 4);
        if visited & bit != 0 {
            return Err(Error::Cycle(at));
        }
        if occupied & bit != 0 {
            return Err(Error::Overlap(at));
        }
        visited |= bit;
        let value = config.read32(at);
        let kind = value as u8;
        let next = (value >> 8) as u8;
        let control = (value >> 16) as u16;
        let bytes = match kind {
            CAP_MSI => {
                if result.msi.is_some() {
                    return Err(Error::Duplicate(kind));
                }
                let address64 = control & (1 << 7) != 0;
                let per_vector_mask = control & (1 << 8) != 0;
                result.msi = Some(Msi {
                    capability: at,
                    enabled: control & 1 != 0,
                    address64,
                    per_vector_mask,
                });
                match (address64, per_vector_mask) {
                    (false, false) => 10,
                    (true, false) => 14,
                    (false, true) => 20,
                    (true, true) => 24,
                }
            }
            CAP_MSIX => {
                if result.msix.is_some() {
                    return Err(Error::Duplicate(kind));
                }
                12
            }
            _ => 4,
        };
        let end = u16::from(at) + bytes;
        if end > CONFIG_BYTES {
            return Err(Error::Truncated(at));
        }
        let words = bytes.div_ceil(4);
        let span = ((1u64 << words) - 1) << (at / 4);
        if span & occupied != 0 {
            return Err(Error::Overlap(at));
        }
        occupied |= span;
        if kind == CAP_MSIX {
            let vectors = (control & 0x7ff) + 1;
            result.msix = Some(Msix {
                capability: at,
                enabled: control & (1 << 15) != 0,
                function_masked: control & (1 << 14) != 0,
                vectors,
                table: region(config.read32(at + 4), u64::from(vectors) * 16)?,
                pending: region(config.read32(at + 8), u64::from(vectors).div_ceil(64) * 8)?,
            });
        }
        at = next;
    }
    Ok(result)
}

#[cfg(test)]
mod tests {
    use super::*;

    struct Config {
        words: [u32; 64],
        reads: usize,
    }

    impl Config {
        fn new() -> Self {
            let mut config = Self {
                words: [0; 64],
                reads: 0,
            };
            config.words[0] = 0x000d_1b36;
            config.words[1] = 1 << 20;
            config.words[0x34 / 4] = 0x40;
            config
        }

        fn cap(&mut self, at: u8, kind: u8, next: u8, control: u16) {
            self.words[usize::from(at / 4)] =
                u32::from(kind) | (u32::from(next) << 8) | (u32::from(control) << 16);
        }

        fn msix(&mut self, vectors: u16, table: u32, pending: u32) {
            self.cap(0x40, CAP_MSIX, 0, vectors - 1);
            self.words[0x44 / 4] = table;
            self.words[0x48 / 4] = pending;
        }
    }

    impl ConfigSpace for Config {
        fn read32(&mut self, offset: u8) -> u32 {
            assert_eq!(offset & 3, 0);
            self.reads += 1;
            assert!(self.reads <= 64, "configuration walk did not terminate");
            self.words[usize::from(offset / 4)]
        }
    }

    #[test]
    fn absent_and_wrong_header_refuse_before_walking() {
        let mut config = Config::new();
        config.words[0] = u32::MAX;
        assert_eq!(discover(&mut config), Err(Error::Absent));
        assert_eq!(config.reads, 1);
        let mut config = Config::new();
        config.words[3] = 0x81 << 16;
        assert_eq!(discover(&mut config), Err(Error::HeaderType(1)));
        assert_eq!(config.reads, 2);
    }

    #[test]
    fn no_list_does_not_follow_the_pointer() {
        let mut config = Config::new();
        config.words[1] = 0;
        config.words[0x34 / 4] = 0xff;
        assert_eq!(discover(&mut config), Ok(Capabilities::default()));
        assert_eq!(config.reads, 3);
    }

    #[test]
    fn all_pointer_values_are_bounded() {
        for pointer in 1..=255u8 {
            let mut config = Config::new();
            config.words[0x34 / 4] = u32::from(pointer);
            let result = discover(&mut config);
            if pointer < 0x40 || pointer & 3 != 0 {
                assert_eq!(result, Err(Error::Pointer(pointer)));
                assert_eq!(config.reads, 4);
            } else {
                assert_eq!(result, Ok(Capabilities::default()));
                assert_eq!(config.reads, 5);
            }
        }
    }

    #[test]
    fn full_list_and_every_cycle_terminate() {
        for tail in (0x40..=0xfcu8).step_by(4).chain([0]) {
            let mut config = Config::new();
            for at in (0x40..0xfcu8).step_by(4) {
                config.cap(at, 0x09, at + 4, 0);
            }
            config.cap(0xfc, 0x09, tail, 0);
            let result = discover(&mut config);
            assert_eq!(config.reads, 52);
            assert_eq!(
                result,
                if tail == 0 {
                    Ok(Capabilities::default())
                } else {
                    Err(Error::Cycle(tail))
                }
            );
        }
    }

    #[test]
    fn backward_links_are_allowed_without_cycles() {
        let mut config = Config::new();
        config.cap(0x40, 0x09, 0x80, 0);
        config.cap(0x80, 0x09, 0x60, 0);
        config.cap(0x60, CAP_MSI, 0, 0x181);
        let msi = discover(&mut config).unwrap().msi.unwrap();
        assert_eq!(
            msi,
            Msi {
                capability: 0x60,
                enabled: true,
                address64: true,
                per_vector_mask: true,
            }
        );
    }

    #[test]
    fn all_msi_shapes_enforce_their_configuration_boundary() {
        for (control, bytes) in [(0, 10u16), (0x80, 14), (0x100, 20), (0x180, 24)] {
            for at in (0x40..=0xfcu8).step_by(4) {
                let mut config = Config::new();
                config.words[0x34 / 4] = u32::from(at);
                config.cap(at, CAP_MSI, 0, control);
                let result = discover(&mut config);
                if u16::from(at) + bytes > 256 {
                    assert_eq!(result, Err(Error::Truncated(at)));
                } else {
                    assert_eq!(result.unwrap().msi.unwrap().capability, at);
                }
            }
        }
    }

    #[test]
    fn duplicate_interrupt_capabilities_refuse() {
        for kind in [CAP_MSI, CAP_MSIX] {
            let mut config = Config::new();
            config.cap(0x40, kind, 0x80, 0);
            config.cap(0x80, kind, 0, 0);
            assert_eq!(discover(&mut config), Err(Error::Duplicate(kind)));
        }
    }

    #[test]
    fn malformed_tail_cannot_return_a_usable_msix() {
        let mut config = Config::new();
        config.msix(1, 0x1000, 0x2000);
        config.cap(0x40, CAP_MSIX, 0xff, 0);
        assert_eq!(discover(&mut config), Err(Error::Pointer(0xff)));
    }

    #[test]
    fn known_capability_registers_cannot_be_headers() {
        let mut config = Config::new();
        config.cap(0x40, CAP_MSI, 0x44, 0);
        assert_eq!(discover(&mut config), Err(Error::Overlap(0x44)));
        // A later, backward capability would cover a header already read.
        let mut config = Config::new();
        config.cap(0x40, 0x09, 0x80, 0);
        config.cap(0x80, 0x09, 0x7c, 0);
        config.cap(0x7c, CAP_MSIX, 0, 0);
        assert_eq!(discover(&mut config), Err(Error::Overlap(0x7c)));
    }

    #[test]
    fn msix_decodes_state_and_complete_region_sizes() {
        for vectors in [1, 64, 65, 2048] {
            let mut config = Config::new();
            config.msix(vectors, 0x1000 | 2, 0x9000 | 4);
            config.words[0x40 / 4] |= 0xc000_0000;
            let msix = discover(&mut config).unwrap().msix.unwrap();
            assert_eq!(msix.vectors, vectors);
            assert!(msix.enabled && msix.function_masked);
            assert_eq!(
                msix.table,
                BarRegion {
                    bar: 2,
                    offset: 0x1000,
                    bytes: u64::from(vectors) * 16
                }
            );
            assert_eq!(
                msix.pending,
                BarRegion {
                    bar: 4,
                    offset: 0x9000,
                    bytes: u64::from(vectors).div_ceil(64) * 8
                }
            );
            assert_eq!(
                msix.validate_regions([None, None, Some(0x10000), None, Some(0x10000), None]),
                Ok(())
            );
        }
    }

    #[test]
    fn msi_and_msix_coexist_in_either_list_order() {
        for msix_first in [false, true] {
            let mut config = Config::new();
            config.cap(
                0x40,
                if msix_first { CAP_MSIX } else { CAP_MSI },
                0x70,
                0x80,
            );
            config.cap(0x70, if msix_first { CAP_MSI } else { CAP_MSIX }, 0, 0x80);
            let at = if msix_first { 0x40 } else { 0x70 };
            config.words[(at + 4) / 4] = 0x3000;
            config.words[(at + 8) / 4] = 0x3800;
            let caps = discover(&mut config).unwrap();
            assert_eq!(caps.msix.unwrap().capability, at as u8);
            assert!(caps.msi.unwrap().address64);
        }
    }

    #[test]
    fn qemu_shaped_msix_table_and_pending_array_fit_bar0() {
        // QEMU 8.2 register locations: hcd-xhci-pci.c, not driver code.
        let mut config = Config::new();
        config.words[0x34 / 4] = 0x90;
        config.cap(0x90, CAP_MSIX, 0, 15);
        config.words[0x94 / 4] = 0x3000;
        config.words[0x98 / 4] = 0x3800;
        let msix = discover(&mut config).unwrap().msix.unwrap();
        assert_eq!(msix.vectors, 16);
        assert_eq!(
            msix.validate_regions([Some(0x4000), None, None, None, None, None]),
            Ok(())
        );
    }

    #[test]
    fn msix_capability_must_fit_before_reading_its_regions() {
        for at in [0xf8, 0xfc] {
            let mut config = Config::new();
            config.words[0x34 / 4] = u32::from(at);
            config.cap(at, CAP_MSIX, 0, 0);
            assert_eq!(discover(&mut config), Err(Error::Truncated(at)));
            assert_eq!(config.reads, 5);
        }
    }

    #[test]
    fn msix_reserved_bar_indices_refuse() {
        for bar in [6, 7] {
            for pending in [false, true] {
                let mut config = Config::new();
                config.msix(
                    1,
                    if pending { 0x1000 } else { 0x1000 | bar },
                    if pending { 0x2000 | bar } else { 0x2000 },
                );
                assert_eq!(discover(&mut config), Err(Error::BarIndex(bar as u8)));
            }
        }
    }

    #[test]
    fn msix_requires_assigned_memory_bars_and_full_extent() {
        let mut config = Config::new();
        config.msix(65, 0x1000 | 2, 0x2000 | 4);
        let msix = discover(&mut config).unwrap().msix.unwrap();
        assert_eq!(
            msix.validate_regions([None; 6]),
            Err(Error::MissingMemoryBar(2))
        );
        let mut bars = [None; 6];
        bars[2] = Some(0x1000 + 65 * 16 - 1);
        bars[4] = Some(0x2010);
        assert_eq!(msix.validate_regions(bars), Err(Error::BarBounds(2)));
        bars[2] = Some(0x1000 + 65 * 16);
        assert_eq!(msix.validate_regions(bars), Ok(()));
        bars[4] = Some(0x200f);
        assert_eq!(msix.validate_regions(bars), Err(Error::BarBounds(4)));
    }

    #[test]
    fn msix_table_and_pending_array_must_not_overlap() {
        let mut config = Config::new();
        config.msix(2, 0x1000, 0x1010);
        let mut msix = discover(&mut config).unwrap().msix.unwrap();
        let bars = [Some(0x10000); 6];
        assert_eq!(msix.validate_regions(bars), Err(Error::MsixOverlap));
        msix.pending.offset = 0x1020;
        assert_eq!(msix.validate_regions(bars), Ok(()));
        msix.pending.offset = 0xff8;
        assert_eq!(msix.validate_regions(bars), Ok(()));
        msix.pending.offset = 0x1000;
        msix.pending.bar = 1;
        assert_eq!(msix.validate_regions(bars), Ok(()));
    }

    #[test]
    fn msix_region_arithmetic_refuses_overflow() {
        let mut config = Config::new();
        config.msix(1, 0x1000, 0x2000);
        let mut msix = discover(&mut config).unwrap().msix.unwrap();
        msix.table.offset = u64::MAX - 7;
        assert_eq!(
            msix.validate_regions([Some(u64::MAX); 6]),
            Err(Error::BarBounds(0))
        );
        msix.table.bar = 6;
        assert_eq!(
            msix.validate_regions([Some(u64::MAX); 6]),
            Err(Error::BarIndex(6))
        );
    }
}
