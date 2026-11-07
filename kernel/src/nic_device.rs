//! One boot-selected NIC: existing 82540 by default, opt-in SPT I219-LM
//! (`net-i219`) or opt-in RTL8125B (`net-rtl8125`, docs/RTL8125.md).
//! This is a closed three-controller dispatch, not a driver registry or new ABI.
use crate::{e1000, i219_device, rtl8125_device};
use absd_kernel::nic::NicInfo;
pub use e1000::{Identity, SendError};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Backend {
    Legacy,
    I219,
    Rtl8125,
}

static mut BACKEND: Backend = Backend::Legacy;
static mut IDENTITY: Option<Identity> = None;
pub enum NicError {
    Absent,
    Legacy(e1000::NicError),
    I219(i219_device::Error),
    Rtl8125(rtl8125_device::ProbeError),
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
            NicError::Rtl8125(error) => f.debug_tuple("Rtl8125").field(error).finish(),
        }
    }
}

/// Called once before probing, with AP device paths excluded by native probe.
/// Normal `net` keeps the existing 82540 implementation unchanged.
pub fn select(backend: Backend) {
    crate::kernel_lock::assert_bsp_device_access();
    unsafe {
        *core::ptr::addr_of_mut!(BACKEND) = backend;
    }
}
fn backend() -> Backend {
    crate::kernel_lock::assert_bsp_device_access();
    unsafe { *core::ptr::addr_of!(BACKEND) }
}
/// Ring geometry for the probe report: (rx descriptors, tx descriptors,
/// buffer bytes). The 82540 and the I219 share e1000_ring's.
pub fn geometry() -> (usize, usize, usize) {
    match backend() {
        Backend::Rtl8125 => rtl8125_device::NIC_GEOMETRY,
        _ => (
            absd_kernel::e1000_ring::RX_DESCRIPTORS,
            absd_kernel::e1000_ring::TX_DESCRIPTORS,
            absd_kernel::e1000_ring::BUFFER_BYTES,
        ),
    }
}
pub fn probe() -> Result<Identity, NicError> {
    let result = match backend() {
        Backend::I219 => i219_device::probe().map_err(|e| match e {
            i219_device::Error::Absent => NicError::Absent,
            e => NicError::I219(e),
        }),
        Backend::Rtl8125 => rtl8125_device::nic_probe().map_err(|e| match e {
            rtl8125_device::ProbeError::Absent => NicError::Absent,
            e => NicError::Rtl8125(e),
        }),
        Backend::Legacy => e1000::probe().map_err(|e| match e {
            e1000::NicError::Absent => NicError::Absent,
            e => NicError::Legacy(e),
        }),
    };
    if let Ok(identity) = result {
        unsafe { *core::ptr::addr_of_mut!(IDENTITY) = Some(identity) };
    }
    result
}

/// Live diagnostic snapshot, obtained only on the serialized BSP device path.
/// No device grant, reinitialization or fault-reset request is issued. The
/// existing driver information path may finish automatic fault containment
/// (including a bus-master fence); this is not caller device-control authority.
pub fn observation() -> [u8; absd_kernel::observation::BYTES] {
    crate::kernel_lock::assert_bsp_device_access();
    let before = crate::sched::now();
    let driver = match backend() {
        Backend::Legacy => 1,
        Backend::I219 => 2,
        Backend::Rtl8125 => 3,
    };
    let initialized = present();
    let identity = unsafe { *core::ptr::addr_of!(IDENTITY) }.map(|identity| {
        (
            u64::from(identity.pci.bus) << 8
                | u64::from(identity.pci.device) << 3
                | u64::from(identity.pci.function),
            identity.mac,
        )
    });
    let info = info();
    absd_kernel::observation::nic_record(
        driver,
        initialized,
        identity,
        info,
        before,
        crate::sched::now(),
    )
}

/// Read-only PCI Ethernet census. Physical jack mapping remains unknown.
pub fn candidate_observation(index: usize) -> Option<[u8; absd_kernel::observation::BYTES]> {
    crate::kernel_lock::assert_bsp_device_access();
    let selected = unsafe { *core::ptr::addr_of!(IDENTITY) }.map(|identity| identity.pci);
    let mut found = None;
    let mut count = 0;
    crate::pci::each(|function| {
        if crate::pci::read32(function, 8) >> 16 != 0x0200 {
            return;
        }
        if count == index {
            let ticks = crate::sched::now();
            let pci = u64::from(function.bus) << 8
                | u64::from(function.device) << 3
                | u64::from(function.function);
            let (vendor, device) = crate::pci::ids(function);
            let revision = (crate::pci::read32(function, 8) & 0xff) as u8;
            found = Some(absd_kernel::observation::candidate_record(
                index,
                pci,
                vendor,
                device,
                selected == Some(function),
                revision,
                ticks,
            ));
        }
        count += 1;
    });
    found
}

pub fn present() -> bool {
    match backend() {
        Backend::I219 => i219_device::present(),
        Backend::Rtl8125 => rtl8125_device::nic_present(),
        Backend::Legacy => e1000::present(),
    }
}
pub fn info() -> Option<NicInfo> {
    crate::contain::poll();
    let info = match backend() {
        Backend::I219 => i219_device::info(),
        Backend::Rtl8125 => rtl8125_device::nic_info(),
        Backend::Legacy => e1000::info(),
    };
    if let Some(info) = &info {
        note_link(info.flags & absd_kernel::nic::NIC_FLAG_LINK_UP != 0);
    }
    info
}
pub fn send(length: u64, fill: impl FnOnce(&mut [u8]) -> bool) -> Result<(), SendError> {
    crate::contain::poll();
    let result = match backend() {
        Backend::I219 => i219_device::send(length, fill),
        Backend::Rtl8125 => rtl8125_device::nic_send(length, fill),
        Backend::Legacy => e1000::send(length, fill),
    };
    crate::contain::poll();
    result
}
pub fn take_frame(deliver: impl FnOnce(&[u8]) -> bool) -> Result<Option<usize>, ()> {
    crate::contain::poll();
    let result = match backend() {
        Backend::I219 => i219_device::take_frame(deliver).map_err(|_| ()),
        Backend::Rtl8125 => rtl8125_device::nic_take_frame(deliver).map_err(|_| ()),
        Backend::Legacy => e1000::take_frame(deliver).map_err(|_| ()),
    };
    crate::contain::poll();
    result
}
pub fn link_up() -> bool {
    crate::contain::poll();
    let up = match backend() {
        Backend::I219 => i219_device::link_up(),
        Backend::Rtl8125 => rtl8125_device::nic_link_up(),
        Backend::Legacy => e1000::link_up(),
    };
    note_link(up);
    up
}

static LINK_SEEN: core::sync::atomic::AtomicU8 =
    core::sync::atomic::AtomicU8::new(absd_kernel::nic_link::LINK_UNSEEN);

/// Reports link changes in plain text: on a machine with only a screen this
/// says whether the cable is in the port this boot drives.
fn note_link(up: bool) {
    use absd_kernel::nic_link::{LINK_DOWN, LINK_UP, link_line};
    use core::sync::atomic::Ordering::Relaxed;
    let state = if up { LINK_UP } else { LINK_DOWN };
    if let Some(line) = link_line(LINK_SEEN.swap(state, Relaxed), up) {
        crate::serial::write(line);
    }
}
/// The general disabled-state precedence for send and receive (docs/NETWORK.md).
pub fn disabled() -> bool {
    match backend() {
        Backend::I219 => i219_device::disabled(),
        Backend::Rtl8125 => rtl8125_device::nic_disabled(),
        Backend::Legacy => e1000::disabled(),
    }
}
pub fn inject_rx_head_fault() -> Option<u32> {
    // This fixture is specific to QEMU e1000. Never write a native ring head.
    match backend() {
        Backend::Legacy => e1000::inject_rx_head_fault(),
        _ => None,
    }
}
/// Arms the transmit-hold qualification fixture (docs/NETWORK.md,
/// "Verification") and reports whether it was armed. Like the ring fault,
/// it is specific to QEMU e1000: refused under `net-i219` and
/// `net-rtl8125`, where it would be inert, so a native boot never reports
/// it armed.
pub fn arm_tx_hold(mode: e1000::TxHold) -> bool {
    match backend() {
        Backend::Legacy => {
            e1000::arm_tx_hold(mode);
            true
        }
        _ => false,
    }
}
