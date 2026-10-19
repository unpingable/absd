//! xHCI scratchpad buffer rules and the scratchpad pool's lifecycle, kept
//! apart from the MMIO driver (`src/xhci.rs`) so they run under `cargo
//! test` on the host. Lane record: docs/xhci-hw-readiness-20261010/RECORD.md.
//!
//! A controller that advertises Max Scratchpad Buffers (HCSPARAMS2) needs
//! that many PAGESIZE-sized, PAGESIZE-aligned buffers for its own private
//! state, listed in a 64-byte-aligned Scratchpad Buffer Array whose address
//! goes in Device Context Base Address Array entry 0, all before Run/Stop
//! is set. The controller may read and write those pages whenever it runs.
//!
//! The driver keeps the buffers in one fixed static pool (no general DMA
//! allocator exists or is added). The pool's states and edges are:
//!
//! ```text
//!   Free --prepare--> Prepared --install--> Installed --reclaim(quiescent)--> Free
//!                       |                      |
//!                       +--abandon--> Free     +--quarantine--> Quarantined (for the boot)
//! ```
//!
//! `Prepared` means ABSD has zeroed the pages and built the array but the
//! controller has not been given DCBAAP; nothing outside ABSD can reach
//! them, so `abandon` returns them at once. `Installed` means the controller
//! may own them. `reclaim` returns them only when the controller is halted
//! and either cannot master the bus or has been reset since it halted;
//! otherwise the pages stay installed (the caller learns `Live`). If the
//! controller never reached that state (it did not halt, or ownership was
//! lost), the pool is quarantined: ABSD never writes those pages again in
//! that boot and no further preparation is possible.

/// Pages in the static pool: the most scratchpad buffers the driver will
/// provide. A controller asking for more is refused by name.
pub const POOL_PAGES: usize = 64;
/// The only scratchpad buffer size this driver provides.
pub const PAGE_BYTES: u64 = 4096;
/// HCSPARAMS2 can encode at most this many buffers (10 bits).
pub const COUNT_LIMIT: u32 = 1023;

/// Max Scratchpad Buffers from HCSPARAMS2: Hi (bits 25:21) above Lo (bits
/// 31:27).
pub fn count(hcsparams2: u32) -> u32 {
    (((hcsparams2 >> 21) & 0x1f) << 5) | (hcsparams2 >> 27)
}

/// HCSPARAMS2.SPR: the controller wants its scratchpads preserved across a
/// save/restore. Reported; this driver never saves or restores.
pub fn restore(hcsparams2: u32) -> bool {
    hcsparams2 & (1 << 26) != 0
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PageSizeError {
    /// PAGESIZE does not offer 4 KiB pages.
    No4KiB(u32),
    /// Scratchpads are required but PAGESIZE offers more than one size, so
    /// the buffer size the controller expects is ambiguous.
    Ambiguous(u32),
}

/// The scratchpad buffer size for this controller, from its PAGESIZE
/// register (bit n: pages of 2^(n+12) bytes). With no scratchpads only
/// 4 KiB support matters (rings and contexts are 4 KiB pages). With
/// scratchpads the controller must offer exactly 4 KiB: the buffer size is
/// the controller's page size, never the host's, and an 8 KiB or larger,
/// or a multi-size, PAGESIZE is refused rather than guessed.
pub fn page_bytes(pagesize: u32, required: u32) -> Result<u64, PageSizeError> {
    let sizes = pagesize & 0xffff;
    if sizes & 1 == 0 {
        return Err(PageSizeError::No4KiB(pagesize));
    }
    if required != 0 && sizes != 1 {
        return Err(PageSizeError::Ambiguous(pagesize));
    }
    Ok(PAGE_BYTES)
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PoolState {
    Free,
    Prepared { pages: u32 },
    Installed { pages: u32 },
    Quarantined { pages: u32 },
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PoolError {
    /// More buffers than the pool holds.
    Exhausted { required: u32, limit: u32 },
    /// The transition is not defined from this state.
    State(PoolState),
    /// Reclaim refused: the controller may still use the pages.
    Live(Quiescence),
    /// The pool was quarantined earlier in this boot.
    Quarantined,
}

/// What the driver observed of the controller when asking to reclaim.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Quiescence {
    /// USBSTS.HCHalted read set.
    pub halted: bool,
    /// The PCI command register's Bus Master Enable read set.
    pub bus_master: bool,
    /// HCRST completed (USBCMD.HCRST and USBSTS.CNR read clear) after the
    /// controller halted.
    pub reset: bool,
}

impl Quiescence {
    /// The controller cannot be using the scratchpads: halted, and either
    /// off the bus or reset since it halted.
    pub fn quiescent(self) -> bool {
        self.halted && (!self.bus_master || self.reset)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Pool {
    state: PoolState,
    limit: u32,
    installs: u64,
}

impl Pool {
    pub const fn new(limit: u32) -> Self {
        Self {
            state: PoolState::Free,
            limit,
            installs: 0,
        }
    }

    pub fn state(&self) -> PoolState {
        self.state
    }

    /// Times the pool has been handed to a controller.
    pub fn installs(&self) -> u64 {
        self.installs
    }

    /// Free -> Prepared: the caller may now zero `required` pages and build
    /// the array. Nothing changes on refusal.
    pub fn prepare(&mut self, required: u32) -> Result<(), PoolError> {
        match self.state {
            PoolState::Free if required == 0 || required > self.limit => {
                Err(PoolError::Exhausted {
                    required,
                    limit: self.limit,
                })
            }
            PoolState::Free => {
                self.state = PoolState::Prepared { pages: required };
                Ok(())
            }
            PoolState::Quarantined { .. } => Err(PoolError::Quarantined),
            state => Err(PoolError::State(state)),
        }
    }

    /// Prepared -> Free: the controller was never given the array.
    pub fn abandon(&mut self) -> Result<(), PoolError> {
        match self.state {
            PoolState::Prepared { .. } => {
                self.state = PoolState::Free;
                Ok(())
            }
            state => Err(PoolError::State(state)),
        }
    }

    /// Prepared -> Installed: the caller is about to give the controller
    /// DCBAAP with the array in entry 0.
    pub fn install(&mut self) -> Result<(), PoolError> {
        match self.state {
            PoolState::Prepared { pages } => {
                self.state = PoolState::Installed { pages };
                self.installs += 1;
                Ok(())
            }
            state => Err(PoolError::State(state)),
        }
    }

    /// Installed -> Free, only when the controller is quiescent. Free stays
    /// Free (nothing was installed).
    pub fn reclaim(&mut self, seen: Quiescence) -> Result<(), PoolError> {
        match self.state {
            PoolState::Free => Ok(()),
            PoolState::Installed { .. } if seen.quiescent() => {
                self.state = PoolState::Free;
                Ok(())
            }
            PoolState::Installed { .. } => Err(PoolError::Live(seen)),
            PoolState::Quarantined { .. } => Err(PoolError::Quarantined),
            state => Err(PoolError::State(state)),
        }
    }

    /// Installed -> Quarantined: the controller was not seen to stop using
    /// the pages. Permanent for the boot. Prepared or Free pages were never
    /// reachable, so there is nothing to quarantine.
    pub fn quarantine(&mut self) {
        if let PoolState::Installed { pages } = self.state {
            self.state = PoolState::Quarantined { pages };
        }
    }

    /// Whether ABSD may write the pool's pages now.
    pub fn writable(&self) -> bool {
        matches!(self.state, PoolState::Prepared { .. })
    }
}

/// Scratchpad Buffer Array alignment.
pub const ARRAY_ALIGN: u64 = 64;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AddressError {
    /// Not aligned to the buffer size (or, for the array, to 64 bytes).
    Unaligned { index: u32, address: u64 },
    /// Outside the memory ABSD knows to be identity-mapped and its own.
    Unowned { index: u32, address: u64 },
    /// Above 4 GiB for a controller without 64-bit addressing.
    Above4GiB { index: u32, address: u64 },
}

/// Checks one DMA page the controller will be given: aligned to `bytes`,
/// wholly inside `owned` (ABSD's identity-mapped, reserved memory), and
/// below 4 GiB unless the controller addresses 64 bits. `index` names the
/// buffer (u32::MAX for the array itself) in the error.
pub fn check_page(
    index: u32,
    address: u64,
    bytes: u64,
    align: u64,
    owned: (u64, u64),
    addresses_64: bool,
) -> Result<(), AddressError> {
    if address == 0 || !address.is_multiple_of(align) {
        return Err(AddressError::Unaligned { index, address });
    }
    let end = address.checked_add(bytes);
    if address < owned.0 || end.is_none_or(|end| end > owned.1) {
        return Err(AddressError::Unowned { index, address });
    }
    if !addresses_64 && end.is_none_or(|end| end > 1 << 32) {
        return Err(AddressError::Above4GiB { index, address });
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hcsparams2(count: u32) -> u32 {
        ((count >> 5) << 21) | ((count & 0x1f) << 27)
    }

    #[test]
    fn count_joins_hi_and_lo() {
        for value in [0, 1, 2, 31, 32, 33, 63, 64, 65, 512, COUNT_LIMIT] {
            assert_eq!(count(hcsparams2(value)), value, "{value}");
        }
        // Other fields do not leak in: IST, ERST Max, and SPR.
        assert_eq!(count(hcsparams2(32) | 0xff | (1 << 26)), 32);
        assert_eq!(count(0xffff_ffff), COUNT_LIMIT);
        // Lo alone would read 32 as zero: the boundary a Lo-only decoder
        // gets wrong.
        assert_eq!(hcsparams2(32) >> 27, 0);
        assert!(restore(1 << 26) && !restore(hcsparams2(COUNT_LIMIT)));
    }

    #[test]
    fn page_size_is_the_controllers_and_exactly_4kib_with_scratchpads() {
        assert_eq!(page_bytes(1, 0), Ok(4096));
        assert_eq!(page_bytes(1, 1), Ok(4096));
        assert_eq!(page_bytes(0x3, 0), Ok(4096));
        assert_eq!(page_bytes(0x3, 1), Err(PageSizeError::Ambiguous(3)));
        assert_eq!(page_bytes(0x2, 0), Err(PageSizeError::No4KiB(2)));
        assert_eq!(page_bytes(0x2, 4), Err(PageSizeError::No4KiB(2)));
        assert_eq!(page_bytes(0, 0), Err(PageSizeError::No4KiB(0)));
        // Reserved upper bits are not page sizes.
        assert_eq!(page_bytes(0x1_0001, 2), Ok(4096));
        assert_eq!(
            page_bytes(0x1_0000, 2),
            Err(PageSizeError::No4KiB(0x1_0000))
        );
    }

    const QUIET_OFF_BUS: Quiescence = Quiescence {
        halted: true,
        bus_master: false,
        reset: false,
    };
    const QUIET_RESET: Quiescence = Quiescence {
        halted: true,
        bus_master: true,
        reset: true,
    };

    #[test]
    fn pool_lifecycle_follows_its_edges() {
        let mut pool = Pool::new(POOL_PAGES as u32);
        assert!(!pool.writable());
        pool.prepare(3).unwrap();
        assert!(pool.writable());
        pool.install().unwrap();
        assert!(!pool.writable());
        assert_eq!(pool.state(), PoolState::Installed { pages: 3 });
        pool.reclaim(QUIET_RESET).unwrap();
        assert_eq!(pool.state(), PoolState::Free);
        pool.prepare(64).unwrap();
        pool.abandon().unwrap();
        assert_eq!(pool.state(), PoolState::Free);
        pool.prepare(1).unwrap();
        pool.install().unwrap();
        pool.reclaim(QUIET_OFF_BUS).unwrap();
        assert_eq!(pool.installs(), 2);
    }

    #[test]
    fn pool_refuses_more_than_it_holds_without_changing() {
        let mut pool = Pool::new(POOL_PAGES as u32);
        assert_eq!(
            pool.prepare(65),
            Err(PoolError::Exhausted {
                required: 65,
                limit: 64
            })
        );
        assert_eq!(
            pool.prepare(COUNT_LIMIT),
            Err(PoolError::Exhausted {
                required: 1023,
                limit: 64
            })
        );
        assert!(pool.prepare(0).is_err());
        assert_eq!(pool.state(), PoolState::Free);
    }

    #[test]
    fn reclaim_while_the_controller_may_run_is_refused() {
        let mut pool = Pool::new(8);
        pool.prepare(2).unwrap();
        pool.install().unwrap();
        for seen in [
            // Running, on the bus.
            Quiescence {
                halted: false,
                bus_master: true,
                reset: false,
            },
            // Off the bus but never seen to halt.
            Quiescence {
                halted: false,
                bus_master: false,
                reset: false,
            },
            // Halted, still on the bus, not reset: its pages may hold state
            // it would use on Run/Stop.
            Quiescence {
                halted: true,
                bus_master: true,
                reset: false,
            },
        ] {
            assert_eq!(pool.reclaim(seen), Err(PoolError::Live(seen)));
            assert_eq!(pool.state(), PoolState::Installed { pages: 2 });
            assert!(!pool.writable());
        }
        // Prepared pages cannot be "reclaimed" and Installed cannot be
        // abandoned or re-prepared.
        assert!(pool.abandon().is_err());
        assert!(pool.prepare(2).is_err());
    }

    #[test]
    fn quarantine_is_permanent() {
        let mut pool = Pool::new(8);
        pool.prepare(2).unwrap();
        pool.install().unwrap();
        pool.quarantine();
        assert_eq!(pool.state(), PoolState::Quarantined { pages: 2 });
        assert_eq!(pool.reclaim(QUIET_OFF_BUS), Err(PoolError::Quarantined));
        assert_eq!(pool.prepare(1), Err(PoolError::Quarantined));
        assert!(!pool.writable());
        // Quarantine of pages never installed changes nothing.
        let mut fresh = Pool::new(8);
        fresh.quarantine();
        assert_eq!(fresh.state(), PoolState::Free);
    }

    #[test]
    fn dma_pages_are_checked() {
        let owned = (0x10_0000, 0x40_0000);
        assert_eq!(check_page(0, 0x20_0000, 4096, 4096, owned, false), Ok(()));
        assert_eq!(
            check_page(1, 0x20_0800, 4096, 4096, owned, false),
            Err(AddressError::Unaligned {
                index: 1,
                address: 0x20_0800
            })
        );
        assert_eq!(
            check_page(2, 0x3f_f000 + 0x1000, 4096, 4096, owned, false),
            Err(AddressError::Unowned {
                index: 2,
                address: 0x40_0000
            })
        );
        assert!(check_page(3, 0, 4096, 4096, owned, true).is_err());
        let high = (0x1_0000_0000, 0x2_0000_0000);
        assert_eq!(
            check_page(4, 0x1_0000_0000, 4096, 4096, high, false),
            Err(AddressError::Above4GiB {
                index: 4,
                address: 0x1_0000_0000
            })
        );
        assert_eq!(check_page(4, 0x1_0000_0000, 4096, 4096, high, true), Ok(()));
        // The array needs only 64-byte alignment.
        assert_eq!(
            check_page(u32::MAX, 0x20_0040, 512, ARRAY_ALIGN, owned, false),
            Ok(())
        );
    }
}
