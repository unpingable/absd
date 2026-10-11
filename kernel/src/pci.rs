//! Just enough PCI for two polled bus-mastering drivers (NVMe and the
//! e1000 NIC): configuration mechanism #1 through ports 0xcf8/0xcfc, a
//! brute-force scan in bus/device/function order, and memory BARs.
//! Firmware has already assigned bus numbers and BAR addresses; nothing
//! here moves them.
//!
//! Device ownership (the tripwire in docs/DESIGN-INFLUENCES.md fired with
//! the NIC): a function has at most one kernel owner for the whole boot.
//! A driver `claim`s the function before it maps a BAR or enables bus
//! mastering, and a second claim of the same function is refused by name.
//! DMA is bus-mastering into static, identity-mapped kernel memory only:
//! no IOMMU is programmed, so no driver ever hands a device a user address.
//! Interrupts stay masked (INTx disabled, no MSI); drivers poll.

use core::arch::asm;

const ADDRESS: u16 = 0xcf8;
const DATA: u16 = 0xcfc;

const COMMAND: u8 = 0x04;
const COMMAND_MEMORY: u16 = 1 << 1;
const COMMAND_BUS_MASTER: u16 = 1 << 2;
const COMMAND_INTX_DISABLE: u16 = 1 << 10;
const BAR0: u8 = 0x10;
/// Distinct functions the kernel may own at once.
const MAX_OWNED: usize = 4;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Function {
    pub bus: u8,
    pub device: u8,
    pub function: u8,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BarError {
    /// BAR0 decodes I/O ports, not memory.
    NotMemory,
    /// The BAR is unassigned (zero).
    Unassigned,
    /// No such BAR, or a 64-bit BAR's upper half was named.
    Index,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ClaimError {
    /// Another driver already owns this function.
    Owned(&'static str),
    /// The ownership table is full.
    Full,
}

static mut OWNERS: [Option<(Function, &'static str)>; MAX_OWNED] = [None; MAX_OWNED];

/// Records `owner` as the one driver of `function` for the rest of the boot.
pub fn claim(function: Function, owner: &'static str) -> Result<(), ClaimError> {
    crate::survey::forbid("pci device claim");
    let owners = unsafe { &mut *core::ptr::addr_of_mut!(OWNERS) };
    if let Some((_, current)) = owners
        .iter()
        .flatten()
        .find(|(owned, _)| *owned == function)
    {
        return Err(ClaimError::Owned(current));
    }
    let slot = owners
        .iter_mut()
        .find(|slot| slot.is_none())
        .ok_or(ClaimError::Full)?;
    *slot = Some((function, owner));
    Ok(())
}

unsafe fn outl(port: u16, value: u32) {
    unsafe {
        asm!("out dx, eax", in("dx") port, in("eax") value, options(nomem, nostack, preserves_flags));
    }
}

unsafe fn inl(port: u16) -> u32 {
    let value: u32;
    unsafe {
        asm!("in eax, dx", in("dx") port, out("eax") value, options(nomem, nostack, preserves_flags));
    }
    value
}

fn select(function: Function, offset: u8) {
    let address = 0x8000_0000
        | (u32::from(function.bus) << 16)
        | (u32::from(function.device) << 11)
        | (u32::from(function.function) << 8)
        | u32::from(offset & 0xfc);
    unsafe { outl(ADDRESS, address) };
}

pub fn read32(function: Function, offset: u8) -> u32 {
    select(function, offset);
    unsafe { inl(DATA) }
}

pub fn write32(function: Function, offset: u8, value: u32) {
    crate::survey::forbid("pci configuration write");
    select(function, offset);
    unsafe { outl(DATA, value) };
}

/// Every present function in bus/device/function order, until `matches`
/// accepts one.
fn scan(mut matches: impl FnMut(Function) -> bool) -> Option<Function> {
    for bus in 0..=255u8 {
        for device in 0..32u8 {
            let first = Function {
                bus,
                device,
                function: 0,
            };
            if read32(first, 0) & 0xffff == 0xffff {
                continue;
            }
            let multifunction = (read32(first, 0x0c) >> 16) & 0x80 != 0;
            let functions = if multifunction { 8 } else { 1 };
            for function in 0..functions {
                let candidate = Function {
                    bus,
                    device,
                    function,
                };
                if read32(candidate, 0) & 0xffff == 0xffff {
                    continue;
                }
                if matches(candidate) {
                    return Some(candidate);
                }
            }
        }
    }
    None
}

/// Calls `visit` for every present function in bus/device/function order.
/// Configuration reads only.
pub fn each(mut visit: impl FnMut(Function)) {
    scan(|candidate| {
        visit(candidate);
        false
    });
}

/// The first function, in bus/device/function order, whose class code,
/// subclass, and programming interface match.
pub fn find(class: u8, subclass: u8, interface: u8) -> Option<Function> {
    scan(|candidate| {
        let code = read32(candidate, 0x08);
        (code >> 24) as u8 == class
            && (code >> 16) as u8 == subclass
            && (code >> 8) as u8 == interface
    })
}

/// The first function with exactly these vendor and device identifiers.
pub fn find_id(vendor: u16, device: u16) -> Option<Function> {
    scan(|candidate| ids(candidate) == (vendor, device))
}

/// `(vendor, device)` identifiers.
pub fn ids(function: Function) -> (u16, u16) {
    let value = read32(function, 0);
    (value as u16, (value >> 16) as u16)
}

/// The physical base of memory BAR0 (32- or 64-bit).
pub fn memory_bar0(function: Function) -> Result<u64, BarError> {
    memory_bar(function, 0)
}

/// The physical base of memory BAR `index` (0..=5; a 64-bit BAR takes two
/// slots, and naming its upper half is refused).
pub fn memory_bar(function: Function, index: u8) -> Result<u64, BarError> {
    if index > 5 {
        return Err(BarError::Index);
    }
    let offset = BAR0 + 4 * index;
    let low = read32(function, offset);
    if low & 1 != 0 {
        return Err(BarError::NotMemory);
    }
    let mut base = u64::from(low & !0xf);
    if (low >> 1) & 3 == 2 {
        if index == 5 {
            return Err(BarError::Index);
        }
        base |= u64::from(read32(function, offset + 4)) << 32;
    }
    if base == 0 {
        return Err(BarError::Unassigned);
    }
    Ok(base)
}

/// Enables memory decoding and bus mastering (the controller DMAs queues
/// and data), and masks legacy INTx: completion is polled.
pub fn enable_polled_dma(function: Function) {
    let value = read32(function, COMMAND);
    let command = (value as u16) | COMMAND_MEMORY | COMMAND_BUS_MASTER | COMMAND_INTX_DISABLE;
    // The upper half is the status register; writing its RW1C bits back as
    // read would clear them, so write zeros there.
    write32(function, COMMAND, u32::from(command));
}
