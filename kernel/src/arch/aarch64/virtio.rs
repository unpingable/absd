//! Modern virtio MMIO, single-vCPU synchronous queues on QEMU's coherent DMA model.
//! Source: OASIS virtio 1.2, MMIO transport and split virtqueue sections.
use core::{
    arch::asm,
    ptr::{read_volatile as read, write_volatile as write},
};
pub const N: usize = 8;
#[derive(Clone, Copy)]
#[repr(C)]
pub struct Descriptor {
    pub address: u64,
    pub length: u32,
    pub flags: u16,
    pub next: u16,
}
impl Descriptor {
    pub const EMPTY: Self = Self {
        address: 0,
        length: 0,
        flags: 0,
        next: 0,
    };
}
#[repr(C)]
pub struct Available {
    flags: u16,
    index: u16,
    ring: [u16; N],
    event: u16,
}
#[derive(Clone, Copy)]
#[repr(C)]
struct Completion {
    id: u32,
    length: u32,
}
#[repr(C)]
struct Used {
    flags: u16,
    index: u16,
    ring: [Completion; N],
    event: u16,
}
#[repr(C, align(4096))]
pub struct Queue {
    pub descriptors: [Descriptor; N],
    available: Available,
    used: Used,
    next: u16,
    published: u16,
    pub base: u64,
    pub number: u32,
    pub failed: bool,
}
impl Queue {
    pub const EMPTY: Self = Self {
        descriptors: [Descriptor::EMPTY; N],
        available: Available {
            flags: 0,
            index: 0,
            ring: [0; N],
            event: 0,
        },
        used: Used {
            flags: 0,
            index: 0,
            ring: [Completion { id: 0, length: 0 }; N],
            event: 0,
        },
        next: 0,
        published: 0,
        base: 0,
        number: 0,
        failed: false,
    };
    pub unsafe fn init(&mut self, base: u64, number: u32) -> Result<(), ()> {
        *self = Self::EMPTY;
        self.base = base;
        self.number = number;
        reg(base, 0x30, number);
        if get(base, 0x34) < N as u32 || get(base, 0x44) != 0 {
            return Err(());
        }
        reg(base, 0x38, N as u32);
        pair(base, 0x80, self.descriptors.as_ptr() as u64);
        pair(base, 0x90, core::ptr::addr_of!(self.available) as u64);
        pair(base, 0xa0, core::ptr::addr_of!(self.used) as u64);
        reg(base, 0x44, 1);
        Ok(())
    }
    pub unsafe fn submit(&mut self, id: u16) -> Result<(), ()> {
        unsafe {
            if self.failed || id >= N as u16 || self.published != self.next {
                return Err(());
            }
            write(
                core::ptr::addr_of_mut!(self.available.ring)
                    .cast::<u16>()
                    .add(self.published as usize % N),
                id,
            );
            asm!("dmb oshst", options(nostack));
            self.published = self.published.wrapping_add(1);
            write(
                core::ptr::addr_of_mut!(self.available.index),
                self.published,
            );
            asm!("dmb oshst", options(nostack));
            reg(self.base, 0x50, self.number);
            Ok(())
        }
    }
    pub unsafe fn poll(&mut self, id: u32, min: u32, max: u32) -> Result<Option<u32>, ()> {
        unsafe {
            if self.failed {
                return Err(());
            }
            let index = read(core::ptr::addr_of!(self.used.index));
            if index == self.next {
                return Ok(None);
            }
            asm!("dmb oshld", options(nostack));
            let completed = read(
                core::ptr::addr_of!(self.used.ring)
                    .cast::<Completion>()
                    .add(self.next as usize % N),
            );
            if !absd_kernel::virtio_completion::valid(
                self.next,
                self.published,
                index,
                completed.id,
                id,
                completed.length,
                (min, max),
            ) {
                self.failed = true;
                reg(self.base, 0x70, 0);
                return Err(());
            }
            self.next = self.next.wrapping_add(1);
            let irq = get(self.base, 0x60);
            reg(self.base, 0x64, irq);
            Ok(Some(completed.length))
        }
    }
    pub unsafe fn wait(&mut self, id: u32, min: u32, max: u32) -> Result<u32, ()> {
        unsafe {
            let deadline = counter() + frequency() / 2;
            loop {
                if let Some(n) = self.poll(id, min, max)? {
                    return Ok(n);
                }
                if counter() >= deadline {
                    self.failed = true;
                    reg(self.base, 0x70, 0);
                    return Err(());
                }
                core::hint::spin_loop();
            }
        }
    }
}
pub fn get(base: u64, offset: u64) -> u32 {
    let v = unsafe { read((base + offset) as *const u32) };
    unsafe {
        asm!("dmb oshld", options(nostack));
    }
    v
}
pub fn reg(base: u64, offset: u64, value: u32) {
    unsafe {
        asm!("dmb oshst", options(nostack));
        write((base + offset) as *mut u32, value);
        asm!("dsb osh", options(nostack));
    }
}
fn pair(base: u64, offset: u64, value: u64) {
    reg(base, offset, value as u32);
    reg(base, offset + 4, (value >> 32) as u32);
}
pub fn frequency() -> u64 {
    let v;
    unsafe {
        asm!("mrs {}, cntfrq_el0",out(reg)v);
    }
    v
}
pub fn counter() -> u64 {
    let v;
    unsafe {
        asm!("mrs {}, cntvct_el0",out(reg)v);
    }
    v
}
pub fn negotiate(base: u64, wanted: u32) -> Result<u32, ()> {
    if get(base, 0) != 0x74726976 || get(base, 4) != 2 {
        return Err(());
    }
    reg(base, 0x70, 0);
    if get(base, 0x70) != 0 {
        return Err(());
    }
    reg(base, 0x70, 3);
    reg(base, 0x14, 1);
    if get(base, 0x10) & 1 == 0 {
        return Err(());
    }
    reg(base, 0x14, 0);
    let features = get(base, 0x10) & wanted;
    reg(base, 0x24, 0);
    reg(base, 0x20, features);
    reg(base, 0x24, 1);
    reg(base, 0x20, 1);
    reg(base, 0x70, 11);
    if get(base, 0x70) & 8 == 0 {
        reg(base, 0x70, 0);
        return Err(());
    }
    Ok(features)
}
pub fn complete(base: u64) {
    reg(base, 0x70, 15);
}
const _: () = {
    assert!(core::mem::size_of::<Descriptor>() == 16);
    assert!(core::mem::size_of::<Completion>() == 8);
};
