//! Bounded split virtqueue for the experimental native PCM driver.
//! Layout and ordering follow VirtIO 1.2 sections 2.7 and 4.1.

use core::cell::{Cell, UnsafeCell};
use core::ptr::{addr_of, addr_of_mut, read_volatile, write_volatile};
use core::sync::atomic::{Ordering, fence};

pub const N: usize = 16;
pub const SLOTS: usize = N / 3;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    Full,
    Device,
    Invalid,
}

#[derive(Clone, Copy)]
pub struct Buffer {
    pub address: u64,
    pub length: u32,
    pub writable: bool,
}

#[repr(C)]
#[derive(Clone, Copy)]
struct Descriptor {
    address: u64,
    length: u32,
    flags: u16,
    next: u16,
}
#[repr(C, align(2))]
struct Available {
    flags: u16,
    index: u16,
    ring: [u16; N],
    event: u16,
}
#[repr(C)]
#[derive(Clone, Copy)]
struct UsedElement {
    id: u32,
    length: u32,
}
#[repr(C, align(4))]
struct Used {
    flags: u16,
    index: u16,
    ring: [UsedElement; N],
    event: u16,
}

/// DMA storage is interior mutable and never covered by an exclusive driver
/// reference. The kernel registers a pinned shared Queue and serializes all CPU
/// access on the BSP. UnsafeCell permits device writes; volatile/fences preserve
/// visibility and ordering, not ownership. Faults retain every outstanding slot.
#[repr(C, align(4096))]
struct Dma {
    descriptors: [Descriptor; N],
    available: Available,
    used: Used,
}
pub struct Queue {
    dma: UnsafeCell<Dma>,
    published: Cell<u16>,
    consumed: Cell<u16>,
    live: Cell<[bool; SLOTS]>,
    writable: Cell<[u32; SLOTS]>,
    failed: Cell<bool>,
}
impl Default for Queue {
    fn default() -> Self {
        Self::new()
    }
}
impl Queue {
    pub const fn new() -> Self {
        Self {
            dma: UnsafeCell::new(Dma {
                descriptors: [Descriptor {
                    address: 0,
                    length: 0,
                    flags: 0,
                    next: 0,
                }; N],
                available: Available {
                    flags: 1,
                    index: 0,
                    ring: [0; N],
                    event: 0,
                },
                used: Used {
                    flags: 0,
                    index: 0,
                    ring: [UsedElement { id: 0, length: 0 }; N],
                    event: 0,
                },
            }),
            published: Cell::new(0),
            consumed: Cell::new(0),
            live: Cell::new([false; SLOTS]),
            writable: Cell::new([0; SLOTS]),
            failed: Cell::new(false),
        }
    }
    /// The caller must pin this Queue before registering these physical addresses
    /// and retain it until device access has ended. No exclusive borrow is used.
    pub fn addresses(&self) -> (u64, u64, u64) {
        unsafe {
            let d = self.dma.get();
            (
                addr_of!((*d).descriptors) as u64,
                addr_of!((*d).available) as u64,
                addr_of!((*d).used) as u64,
            )
        }
    }
    pub fn outstanding(&self) -> usize {
        self.live.get().iter().filter(|v| **v).count()
    }
    pub fn free_slot(&self) -> Result<usize, Error> {
        if self.failed.get() {
            return Err(Error::Device);
        }
        self.live.get().iter().position(|v| !*v).ok_or(Error::Full)
    }
    pub fn submit(&self, buffers: [Buffer; 3]) -> Result<u16, Error> {
        let slot = self.free_slot()?;
        let mut writable = 0u32;
        let mut seen_write = false;
        for b in buffers {
            if b.length == 0
                || b.address.checked_add(b.length as u64).is_none()
                || (seen_write && !b.writable)
            {
                return Err(Error::Invalid);
            }
            if b.writable {
                seen_write = true;
                writable = writable.checked_add(b.length).ok_or(Error::Invalid)?;
            }
        }
        let head = slot * 3;
        let published = self.published.get();
        unsafe {
            let d = self.dma.get();
            for (i, b) in buffers.iter().enumerate() {
                write_volatile(
                    addr_of_mut!((*d).descriptors[head + i]),
                    Descriptor {
                        address: b.address,
                        length: b.length,
                        flags: if i < 2 { 1 } else { 0 } | if b.writable { 2 } else { 0 },
                        next: if i < 2 { (head + i + 1) as u16 } else { 0 },
                    },
                );
            }
            let mut live = self.live.get();
            live[slot] = true;
            self.live.set(live);
            let mut sizes = self.writable.get();
            sizes[slot] = writable;
            self.writable.set(sizes);
            write_volatile(
                addr_of_mut!((*d).available.ring[published as usize % N]),
                head as u16,
            );
            fence(Ordering::Release);
            let next = published.wrapping_add(1);
            self.published.set(next);
            write_volatile(addr_of_mut!((*d).available.index), next);
            fence(Ordering::SeqCst);
        }
        Ok(head as u16)
    }
    pub fn poll(&self) -> Result<Option<(u16, u32)>, Error> {
        if self.failed.get() {
            return Err(Error::Device);
        }
        let consumed = self.consumed.get();
        let index = unsafe { read_volatile(addr_of!((*self.dma.get()).used.index)) };
        if index == consumed {
            return Ok(None);
        }
        fence(Ordering::Acquire);
        if index.wrapping_sub(consumed) as usize > self.outstanding() {
            return self.fault();
        }
        let entry =
            unsafe { read_volatile(addr_of!((*self.dma.get()).used.ring[consumed as usize % N])) };
        let slot = entry.id as usize / 3;
        let mut live = self.live.get();
        if entry.id % 3 != 0
            || slot >= SLOTS
            || !live[slot]
            || entry.length > self.writable.get()[slot]
        {
            return self.fault();
        }
        live[slot] = false;
        self.live.set(live);
        self.consumed.set(consumed.wrapping_add(1));
        Ok(Some((entry.id as u16, entry.length)))
    }
    fn fault<T>(&self) -> Result<T, Error> {
        self.failed.set(true);
        Err(Error::Device)
    }
}
const _: () = {
    assert!(core::mem::size_of::<Descriptor>() == 16);
    assert!(core::mem::size_of::<UsedElement>() == 8);
};

#[cfg(test)]
mod tests {
    use super::*;

    fn buffers() -> [Buffer; 3] {
        [
            Buffer {
                address: 0x1000,
                length: 4,
                writable: false,
            },
            Buffer {
                address: 0x2000,
                length: 1920,
                writable: false,
            },
            Buffer {
                address: 0x3000,
                length: 8,
                writable: true,
            },
        ]
    }
    // A device writes used entries independently of the driver bookkeeping.
    fn complete(q: &mut Queue, head: u32, len: u32) {
        let n = unsafe { (*q.dma.get()).used.index };
        unsafe {
            (*q.dma.get()).used.ring[n as usize % N] = UsedElement {
                id: head,
                length: len,
            };
        }
        unsafe {
            (*q.dma.get()).used.index = n.wrapping_add(1);
        }
    }
    #[test]
    fn free_slot_tracks_dma_ownership() {
        let mut q = Queue::new();
        assert_eq!(q.free_slot(), Ok(0));
        let head = q.submit(buffers()).unwrap();
        assert_eq!(q.free_slot(), Ok(1));
        complete(&mut q, head as u32, 8);
        q.poll().unwrap();
        assert_eq!(q.free_slot(), Ok(0));
        q.failed.set(true);
        assert_eq!(q.free_slot(), Err(Error::Device));
    }

    #[test]
    fn saturation_does_not_overwrite_live_chains() {
        let mut q = Queue::new();
        let heads: [_; SLOTS] = core::array::from_fn(|_| q.submit(buffers()).unwrap());
        assert_eq!(q.submit(buffers()), Err(Error::Full));
        assert_eq!(q.outstanding(), SLOTS);
        for head in heads {
            complete(&mut q, head as u32, 8);
        }
        for head in heads {
            assert_eq!(q.poll(), Ok(Some((head, 8))));
        }
        assert_eq!(q.outstanding(), 0);
        assert!(q.submit(buffers()).is_ok());
    }
    #[test]
    fn out_of_order_completion_releases_only_that_chain() {
        let mut q = Queue::new();
        let a = q.submit(buffers()).unwrap();
        let b = q.submit(buffers()).unwrap();
        complete(&mut q, b as u32, 8);
        assert_eq!(q.poll(), Ok(Some((b, 8))));
        assert_eq!(q.submit(buffers()), Ok(b));
        complete(&mut q, a as u32, 8);
        assert_eq!(q.poll(), Ok(Some((a, 8))));
    }
    #[test]
    fn malformed_completion_quarantines_every_live_chain() {
        for (head, length) in [(1, 8), (15, 8), (99, 8), (0, 9)] {
            let mut q = Queue::new();
            q.submit(buffers()).unwrap();
            complete(&mut q, head, length);
            assert_eq!(q.poll(), Err(Error::Device));
            assert_eq!(q.outstanding(), 1);
            assert_eq!(q.submit(buffers()), Err(Error::Device));
            assert_eq!(q.poll(), Err(Error::Device));
        }
    }
    #[test]
    fn duplicate_and_excess_index_are_faults() {
        let mut q = Queue::new();
        let a = q.submit(buffers()).unwrap();
        q.submit(buffers()).unwrap();
        complete(&mut q, a as u32, 8);
        complete(&mut q, a as u32, 8);
        assert!(q.poll().unwrap().is_some());
        assert_eq!(q.poll(), Err(Error::Device));
        let q = Queue::new();
        q.submit(buffers()).unwrap();
        unsafe {
            (*q.dma.get()).used.index = 2;
        }
        assert_eq!(q.poll(), Err(Error::Device));
    }
    #[test]
    fn invalid_buffers_do_not_publish_or_consume_slots() {
        let q = Queue::new();
        for bad in [
            Buffer {
                address: u64::MAX,
                length: 8,
                writable: true,
            },
            Buffer {
                address: 0x3000,
                length: 0,
                writable: true,
            },
        ] {
            let mut b = buffers();
            b[2] = bad;
            assert_eq!(q.submit(b), Err(Error::Invalid));
            assert_eq!(q.outstanding(), 0);
            assert_eq!(unsafe { (*q.dma.get()).available.index }, 0);
        }
        let mut b = buffers();
        b[0].writable = true;
        assert_eq!(q.submit(b), Err(Error::Invalid));
        assert_eq!(q.outstanding(), 0);
    }

    #[test]
    fn indices_wrap_without_losing_ownership() {
        let mut q = Queue::new();
        for _ in 0..65540 {
            let head = q.submit(buffers()).unwrap();
            complete(&mut q, head as u32, 8);
            assert_eq!(q.poll(), Ok(Some((head, 8))));
        }
        assert_eq!(q.poll(), Ok(None));
        assert_eq!(q.outstanding(), 0);
    }
}
