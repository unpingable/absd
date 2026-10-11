use super::virtio::{self, Descriptor, Queue};
#[derive(Clone, Copy, Debug)]
pub enum BlockError {
    Absent,
    OutOfRange,
    ReadOnly,
    Device,
    Timeout,
}
#[repr(C)]
struct Request {
    kind: u32,
    reserved: u32,
    sector: u64,
}
static mut QUEUE: Queue = Queue::EMPTY;
static mut REQUEST: Request = Request {
    kind: 0,
    reserved: 0,
    sector: 0,
};
static mut BUFFER: [u8; 512] = [0; 512];
static mut STATUS: u8 = 0xff;
static mut CAPACITY: u64 = 0;
static mut WRITE: bool = false;
static mut FLUSH: bool = false;
static mut BASE: u64 = 0;
pub fn init(base: u64) -> Result<(), BlockError> {
    unsafe {
        let features =
            virtio::negotiate(base, (1 << 5) | (1 << 9)).map_err(|_| BlockError::Device)?;
        WRITE = features & (1 << 5) == 0;
        FLUSH = features & (1 << 9) != 0;
        // Stable configuration generation around the split 64-bit capacity.
        let mut capacity = None;
        for _ in 0..8 {
            let configuration_generation = virtio::get(base, 0xfc);
            let lo = virtio::get(base, 0x100);
            let hi = virtio::get(base, 0x104);
            if configuration_generation == virtio::get(base, 0xfc) {
                capacity = Some(lo as u64 | ((hi as u64) << 32));
                break;
            }
        }
        CAPACITY = capacity.filter(|x| *x > 0).ok_or(BlockError::Device)?;
        (&mut *core::ptr::addr_of_mut!(QUEUE))
            .init(base, 0)
            .map_err(|_| BlockError::Device)?;
        BASE = base;
        virtio::complete(base);
        Ok(())
    }
}
pub fn writable() -> bool {
    unsafe { WRITE }
}
pub fn sector_count() -> Option<u64> {
    unsafe { if BASE == 0 { None } else { Some(CAPACITY) } }
}
fn request(kind: u32, lba: u64) -> Result<(), BlockError> {
    unsafe {
        if BASE == 0 {
            return Err(BlockError::Absent);
        }
        if kind != 4 && lba >= CAPACITY {
            return Err(BlockError::OutOfRange);
        }
        if kind != 0 && !WRITE {
            return Err(BlockError::ReadOnly);
        }
        if kind == 4 && !FLUSH {
            return Err(BlockError::Device);
        }
        REQUEST = Request {
            kind,
            reserved: 0,
            sector: lba,
        };
        STATUS = 0xff;
        let q = &mut *core::ptr::addr_of_mut!(QUEUE);
        q.descriptors[0] = Descriptor {
            address: core::ptr::addr_of!(REQUEST) as u64,
            length: 16,
            flags: 1,
            next: if kind == 4 { 2 } else { 1 },
        };
        q.descriptors[1] = Descriptor {
            address: core::ptr::addr_of!(BUFFER) as u64,
            length: 512,
            flags: 1 | if kind == 0 { 2 } else { 0 },
            next: 2,
        };
        q.descriptors[2] = Descriptor {
            address: core::ptr::addr_of!(STATUS) as u64,
            length: 1,
            flags: 2,
            next: 0,
        };
        q.submit(0).map_err(|_| BlockError::Device)?;
        let expected = if kind == 0 { 513 } else { 1 };
        q.wait(0, expected, expected)
            .map_err(|_| BlockError::Timeout)?;
        if core::ptr::read_volatile(core::ptr::addr_of!(STATUS)) != 0 {
            return Err(BlockError::Device);
        }
        Ok(())
    }
}
pub fn read_sector(lba: u64, d: &mut [u8; 512]) -> Result<(), BlockError> {
    request(0, lba)?;
    unsafe {
        core::ptr::copy_nonoverlapping(core::ptr::addr_of!(BUFFER).cast(), d.as_mut_ptr(), 512);
    }
    Ok(())
}
pub fn write_sector(lba: u64, d: &[u8; 512]) -> Result<(), BlockError> {
    unsafe {
        core::ptr::copy_nonoverlapping(d.as_ptr(), core::ptr::addr_of_mut!(BUFFER).cast(), 512);
    }
    request(1, lba)
}
pub fn flush() -> Result<(), BlockError> {
    request(4, 0)
}
/// Reads `d.len() / 512` consecutive sectors from `lba`, one request per
/// sector on this transport; one result covers the span, which is checked
/// against the capacity before the first request.
pub fn read_sectors(lba: u64, d: &mut [u8]) -> Result<(), BlockError> {
    let sectors = span(lba, d.len())?;
    for (index, sector) in d
        .as_chunks_mut::<512>()
        .0
        .iter_mut()
        .enumerate()
        .take(sectors)
    {
        read_sector(lba + index as u64, sector)?;
    }
    Ok(())
}
/// Writes `d.len() / 512` consecutive sectors from `lba`, one request per
/// sector on this transport; a failure leaves zero or more leading sectors
/// on the device.
pub fn write_sectors(lba: u64, d: &[u8]) -> Result<(), BlockError> {
    let sectors = span(lba, d.len())?;
    for (index, sector) in d.as_chunks::<512>().0.iter().enumerate().take(sectors) {
        write_sector(lba + index as u64, sector)?;
    }
    Ok(())
}
fn span(lba: u64, bytes: usize) -> Result<usize, BlockError> {
    let sectors = bytes / 512;
    if bytes == 0 || !bytes.is_multiple_of(512) || sectors > 8 {
        return Err(BlockError::OutOfRange);
    }
    let capacity = unsafe { core::ptr::read_volatile(core::ptr::addr_of!(CAPACITY)) };
    let end = lba
        .checked_add(sectors as u64)
        .ok_or(BlockError::OutOfRange)?;
    if end > capacity {
        return Err(BlockError::OutOfRange);
    }
    Ok(sectors)
}
