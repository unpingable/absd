use super::virtio::{self, Descriptor, Queue};
use absd_kernel::nic::{NIC_FRAME_MAX, NIC_FRAME_MIN, NicInfo};
static mut RX: Queue = Queue::EMPTY;
static mut TX: Queue = Queue::EMPTY;
static mut RXBUF: [u8; 1526] = [0; 1526];
static mut TXBUF: [u8; 1526] = [0; 1526];
static mut BASE: u64 = 0;
static mut MAC: [u8; 6] = [0; 6];
static mut FAILED: bool = false;
static mut COUNTS: [u64; 6] = [0; 6];
pub enum SendError {
    Length,
    Copy,
    Disabled,
    /// Never produced here: virtio-net makes no carrier distinction, so a
    /// failed send is `Disabled`. The variant exists so the shared
    /// `nic_send` match (src/syscalls/nic.rs) compiles for this target;
    /// whether virtio-net should report a link outcome is an owner
    /// question (D-05 ruling ii), recorded, not acted on.
    #[allow(dead_code)]
    NoCarrier,
}
pub enum ReceiveError {
    Disabled,
    Copy,
}
pub fn init(base: u64) -> Result<(), ()> {
    unsafe {
        let f = virtio::negotiate(base, 1 << 5)?;
        if f & (1 << 5) == 0 {
            return Err(());
        }
        for (i, slot) in (&mut *core::ptr::addr_of_mut!(MAC)).iter_mut().enumerate() {
            *slot = core::ptr::read_volatile((base + 0x100 + i as u64) as *const u8);
        }

        (&mut *core::ptr::addr_of_mut!(RX)).init(base, 0)?;
        (&mut *core::ptr::addr_of_mut!(TX)).init(base, 1)?;
        BASE = base;
        post_rx()?;
        virtio::complete(base);
        Ok(())
    }
}
unsafe fn post_rx() -> Result<(), ()> {
    unsafe {
        let rx = &mut *core::ptr::addr_of_mut!(RX);
        rx.descriptors[0] = Descriptor {
            address: core::ptr::addr_of!(RXBUF) as u64,
            length: 1526,
            flags: 2,
            next: 0,
        };
        rx.submit(0)
    }
}
pub fn present() -> bool {
    unsafe { BASE != 0 && !FAILED }
}
pub fn disabled() -> bool {
    unsafe { FAILED }
}
pub fn info() -> Option<NicInfo> {
    if !present() {
        return None;
    }
    Some(NicInfo {
        mac: unsafe { MAC },
        flags: absd_kernel::nic::NIC_FLAG_LINK_UP,
        rx_frames: unsafe { COUNTS[0] },
        rx_refused: unsafe { COUNTS[1] },
        rx_missed: unsafe { COUNTS[2] },
        tx_frames: unsafe { COUNTS[3] },
        tx_refused: unsafe { COUNTS[4] },
        tx_errors: unsafe { COUNTS[5] },
    })
}
pub fn send(length: u64, copy: impl FnOnce(&mut [u8]) -> bool) -> Result<(), SendError> {
    unsafe {
        if !present() {
            return Err(SendError::Disabled);
        }
        if !(NIC_FRAME_MIN as u64..=NIC_FRAME_MAX as u64).contains(&length) {
            COUNTS[4] += 1;
            return Err(SendError::Length);
        }
        let n = length as usize;
        let buf = &mut *core::ptr::addr_of_mut!(TXBUF);
        buf.fill(0);
        if !copy(&mut buf[12..12 + n]) {
            COUNTS[4] += 1;
            return Err(SendError::Copy);
        }
        let q = &mut *core::ptr::addr_of_mut!(TX);
        q.descriptors[0] = Descriptor {
            address: buf.as_ptr() as u64,
            length: (12 + n.max(60)) as u32,
            flags: 0,
            next: 0,
        };
        if q.submit(0).and_then(|_| q.wait(0, 0, 0)).is_err() {
            FAILED = true;
            COUNTS[5] += 1;
            return Err(SendError::Disabled);
        }
        COUNTS[3] += 1;
        Ok(())
    }
}
pub fn take_frame(copy: impl FnOnce(&[u8]) -> bool) -> Result<Option<usize>, ReceiveError> {
    unsafe {
        if !present() {
            return if FAILED {
                Err(ReceiveError::Disabled)
            } else {
                Ok(None)
            };
        }
        let q = &mut *core::ptr::addr_of_mut!(RX);
        let Some(n) = q
            .poll(0, 12 + NIC_FRAME_MIN as u32, 12 + NIC_FRAME_MAX as u32)
            .map_err(|_| {
                FAILED = true;
                ReceiveError::Disabled
            })?
        else {
            return Ok(None);
        };
        let buf = &*core::ptr::addr_of!(RXBUF);
        if buf[..10] != [0; 10] {
            FAILED = true;
            return Err(ReceiveError::Disabled);
        }
        let len = n as usize - 12;
        let copied = copy(&buf[12..12 + len]);
        post_rx().map_err(|_| {
            FAILED = true;
            ReceiveError::Disabled
        })?;
        COUNTS[0] += 1;
        if !copied {
            COUNTS[1] += 1;
            return Err(ReceiveError::Copy);
        }
        Ok(Some(len))
    }
}
