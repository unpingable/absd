//! One boot-selected NIC: existing 82540 by default, opt-in SPT I219-LM.
//! This is a closed two-controller dispatch, not a driver registry or new ABI.
use crate::{e1000, i219_device};
use absd_kernel::nic::NicInfo;
pub use e1000::{Identity, SendError};

static mut NATIVE: bool = false;
pub enum NicError {
    Absent,
    Legacy(e1000::NicError),
    I219(i219_device::Error),
}

/// A legacy refusal prints in the 82540 driver's own form (`Map { .. }`,
/// as the startup qualification scripts match it); `Absent` and the I219
/// forms are unchanged.
impl core::fmt::Debug for NicError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            NicError::Absent => f.write_str("Absent"),
            NicError::Legacy(error) => core::fmt::Debug::fmt(error, f),
            NicError::I219(error) => f.debug_tuple("I219").field(error).finish(),
        }
    }
}

/// Called once before probing, with AP device paths excluded by native probe.
/// Normal `net` keeps the existing 82540 implementation unchanged.
pub fn select_i219(native: bool) {
    crate::kernel_lock::assert_bsp_device_access();
    unsafe {
        *core::ptr::addr_of_mut!(NATIVE) = native;
    }
}
fn native() -> bool {
    crate::kernel_lock::assert_bsp_device_access();
    unsafe { *core::ptr::addr_of!(NATIVE) }
}
pub fn probe() -> Result<Identity, NicError> {
    if native() {
        i219_device::probe().map_err(|e| match e {
            i219_device::Error::Absent => NicError::Absent,
            e => NicError::I219(e),
        })
    } else {
        e1000::probe().map_err(|e| match e {
            e1000::NicError::Absent => NicError::Absent,
            e => NicError::Legacy(e),
        })
    }
}
pub fn present() -> bool {
    if native() {
        i219_device::present()
    } else {
        e1000::present()
    }
}
pub fn info() -> Option<NicInfo> {
    if native() {
        i219_device::info()
    } else {
        e1000::info()
    }
}
pub fn send(length: u64, fill: impl FnOnce(&mut [u8]) -> bool) -> Result<(), SendError> {
    if native() {
        i219_device::send(length, fill)
    } else {
        e1000::send(length, fill)
    }
}
pub fn take_frame(deliver: impl FnOnce(&[u8]) -> bool) -> Result<Option<usize>, ()> {
    if native() {
        i219_device::take_frame(deliver).map_err(|_| ())
    } else {
        e1000::take_frame(deliver).map_err(|_| ())
    }
}
pub fn link_up() -> bool {
    if native() {
        i219_device::link_up()
    } else {
        e1000::link_up()
    }
}
/// The general disabled-state precedence for send and receive (docs/NETWORK.md).
pub fn disabled() -> bool {
    if native() {
        i219_device::disabled()
    } else {
        e1000::disabled()
    }
}
pub fn inject_rx_head_fault() -> Option<u32> {
    // This fixture is specific to QEMU e1000. Never write a native ring head.
    if native() {
        None
    } else {
        e1000::inject_rx_head_fault()
    }
}
/// Arms the transmit-hold qualification fixture (docs/NETWORK.md,
/// "Verification") and reports whether it was armed. Like the ring fault,
/// it is specific to QEMU e1000: refused under `net-i219`, where it would
/// be inert, so a native boot never reports it armed.
pub fn arm_tx_hold(mode: e1000::TxHold) -> bool {
    if native() {
        false
    } else {
        e1000::arm_tx_hold(mode);
        true
    }
}
