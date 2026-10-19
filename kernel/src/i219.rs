/******************************************************************************
  SPDX-License-Identifier: BSD-3-Clause

  Copyright (c) 2001-2020, Intel Corporation
  All rights reserved.

  Redistribution and use in source and binary forms, with or without
  modification, are permitted provided that the following conditions are met:

   1. Redistributions of source code must retain the above copyright notice,
      this list of conditions and the following disclaimer.

   2. Redistributions in binary form must reproduce the above copyright
      notice, this list of conditions and the following disclaimer in the
      documentation and/or other materials provided with the distribution.

   3. Neither the name of the Intel Corporation nor the names of its
      contributors may be used to endorse or promote products derived from
      this software without specific prior written permission.

  THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
  AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
  IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
  ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE
  LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
  CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
  SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
  INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
  CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
  ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
  POSSIBILITY OF SUCH DAMAGE.

******************************************************************************/

//! Bounded Intel Sunrise Point-H I219-LM (8086:15b7) bring-up.
//!
//! Register sequences adapted from Intel's BSD-licensed FreeBSD shared code,
//! revision 833d39bd2e38421a14ea489a956261a0fa993fbc, e1000_ich8lan.c,
//! e1000_phy.c and if_em.c. This is deliberately a cold, unmanaged, PCIe-mode,
//! hardware-configured PHY profile, not support for every I219 firmware mode.
//! No NVM writes, firmware requests, inherited ring flushes, or PHY power cycles.
//! The caller owns PCI BAR validation, uncacheable MMIO mapping, DMA memory and
//! PCI bus mastering. All DMA allocations must remain pinned after activation;
//! this module does not establish a reset/reclamation or generation-transfer API.

pub const PCI_ID: u32 = 0x15b7_8086;
pub const MMIO_BYTES: u64 = 0x20_000;
const CTRL: u32 = 0;
const STATUS: u32 = 8;
const STRAP: u32 = 0x0c;
const CTRL_EXT: u32 = 0x18;
const MDIC: u32 = 0x20;
const FEXTNVM: u32 = 0x28;
const EXTCNF_CTRL: u32 = 0xf00;
const FWSM: u32 = 0x5b54;
const RCTL: u32 = 0x100;
const TCTL: u32 = 0x400;
const IMC: u32 = 0xd8;
const SWFLAG: u32 = 0x20;
const PHY_RESET: u32 = 1 << 31;
const MAC_RESET: u32 = 1 << 26;
const PHY_ID: u32 = 0x0154_00a0;

/// Implementations must use ordered volatile MMIO and serialize this device.
/// A successful delay must measure actual time, not a guessed CPU loop count.
pub trait Io {
    fn read32(&mut self, offset: u32) -> u32;
    fn write32(&mut self, offset: u32, value: u32);
    fn read_config32(&mut self, offset: u8) -> u32;
    fn delay_ms(&mut self, milliseconds: u32) -> bool;
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    UnsupportedDevice,
    FirmwareOwned,
    ResetBlocked,
    LowPowerState,
    SoftwarePhyConfiguration,
    InheritedDescriptors,
    SemaphoreBusy,
    MdioTimeout,
    MdioError,
    MdioResponseMismatch,
    UnsupportedPhy,
    MasterDrainTimeout,
    TimerUnavailable,
    /// Reset was issued but the mandatory no-MMIO interval was not established.
    /// Do not access MMIO or retry initialization following this result.
    ResetRecoveryRequired,
    ResetTimeout,
    NvmConfigurationTimeout,
    InvalidMac,
    InvalidRing,
    InvalidPacketBuffer,
    InvalidLatencyConfiguration,
    LinkDown,
    UnsupportedLink,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Initialized {
    pub mac: [u8; 6],
    pub phy_id: u32,
    /// No cable or incomplete negotiation is not a controller failure.
    pub link_up: bool,
}

fn update(io: &mut impl Io, reg: u32, clear: u32, set: u32) {
    let value = io.read32(reg);
    io.write32(reg, (value & !clear) | set);
}

fn delay(io: &mut impl Io, ms: u32) -> Result<(), Error> {
    if io.delay_ms(ms) {
        Ok(())
    } else {
        Err(Error::TimerUnavailable)
    }
}

fn poll(
    io: &mut impl Io,
    reg: u32,
    mask: u32,
    expected: u32,
    attempts: u32,
    error: Error,
) -> Result<(), Error> {
    for _ in 0..attempts {
        if io.read32(reg) & mask == expected {
            return Ok(());
        }
        delay(io, 1)?;
    }
    Err(error)
}

fn acquire(io: &mut impl Io) -> Result<(), Error> {
    poll(io, EXTCNF_CTRL, SWFLAG, 0, 100, Error::SemaphoreBusy)?;
    update(io, EXTCNF_CTRL, 0, SWFLAG);
    match poll(io, EXTCNF_CTRL, SWFLAG, SWFLAG, 1000, Error::SemaphoreBusy) {
        Ok(()) => Ok(()),
        Err(e) => {
            update(io, EXTCNF_CTRL, SWFLAG, 0);
            Err(e)
        }
    }
}

fn release(io: &mut impl Io) {
    update(io, EXTCNF_CTRL, SWFLAG, 0);
}

fn mdic(io: &mut impl Io, address: u8, reg: u8, value: Option<u16>) -> Result<u16, Error> {
    let command = ((address as u32) << 21)
        | ((reg as u32) << 16)
        | if value.is_some() {
            0x0400_0000
        } else {
            0x0800_0000
        }
        | u32::from(value.unwrap_or(0));
    io.write32(MDIC, command);
    // Intel shared code permits 3 * 640 * 50us = 96ms.
    for _ in 0..96 {
        delay(io, 1)?;
        let result = io.read32(MDIC);
        if result & 0x1000_0000 == 0 {
            continue;
        }
        if result & 0x4000_0000 != 0 {
            return Err(Error::MdioError);
        }
        if result & 0x03ff_0000 != command & 0x03ff_0000 {
            return Err(Error::MdioResponseMismatch);
        }
        return Ok(result as u16);
    }
    Err(Error::MdioTimeout)
}

// HV PHY addressing: pages >=768 use MDIO address 1, basic page 0 address 2.
// Page selector itself always uses address 1. No debug/wakeup-page accesses.
fn phy(io: &mut impl Io, page: u16, reg: u8, value: Option<u16>) -> Result<u16, Error> {
    debug_assert!(page == 0 || (768..800).contains(&page));
    if reg > 15 {
        mdic(io, 1, 31, Some(if page == 768 { 0 } else { page << 5 }))?;
    }
    mdic(io, if page >= 768 { 1 } else { 2 }, reg, value)
}

fn phy_update(io: &mut impl Io, page: u16, reg: u8, clear: u16, set: u16) -> Result<(), Error> {
    let value = phy(io, page, reg, None)?;
    phy(io, page, reg, Some((value & !clear) | set))?;
    Ok(())
}

fn check_profile(io: &mut impl Io) -> Result<(), Error> {
    let fw = io.read32(FWSM);
    if fw & 0x8000 != 0 {
        return Err(Error::FirmwareOwned);
    }
    if fw & 0x40 == 0 {
        return Err(Error::ResetBlocked);
    }
    if fw & 0x400 != 0 || io.read32(CTRL_EXT) & 0x800 != 0 {
        return Err(Error::LowPowerState);
    }
    if io.read32(FEXTNVM) & (1 << 27) != 0 {
        return Err(Error::SoftwarePhyConfiguration);
    }
    Ok(())
}

fn check_phy_profile(io: &mut impl Io) -> Result<u32, Error> {
    let id = ((phy(io, 0, 2, None)? as u32) << 16) | phy(io, 0, 3, None)? as u32;
    if id & !0xf != PHY_ID {
        return Err(Error::UnsupportedPhy);
    }
    if phy(io, 0, 0, None)? & ((1 << 11) | (1 << 10)) != 0
        || phy(io, 769, 23, None)? & 1 != 0
        || phy(io, 779, 16, None)? & 0x1d75 != 0
    {
        return Err(Error::LowPowerState);
    }
    Ok(id)
}

/// Reset and initialize only the explicitly matched unmanaged SPT-H profile.
/// Neither RX/TX DMA engine is enabled by this function. On error the caller
/// must not publish the NIC. Unsupported preflight states are not reset.
pub fn initialize(io: &mut impl Io) -> Result<Initialized, Error> {
    if io.read_config32(0) != PCI_ID {
        return Err(Error::UnsupportedDevice);
    }
    check_profile(io)?;
    // Do not flush unknown firmware-owned rings or reset the SPT pending state.
    if io.read_config32(0xe4) & 0x100 != 0 || io.read32(RCTL) & 2 != 0 || io.read32(TCTL) & 2 != 0 {
        return Err(Error::InheritedDescriptors);
    }
    delay(io, 1)?;
    acquire(io)?;
    let preflight = check_phy_profile(io);
    release(io);
    preflight?;

    // Block new DMA, drain existing requests before changing hardware state.
    update(io, CTRL, 0, 4);
    poll(io, STATUS, 0x80000, 0, 100, Error::MasterDrainTimeout)?;
    io.write32(IMC, u32::MAX);
    io.write32(RCTL, 0);
    io.write32(TCTL, 8);
    io.read32(STATUS);
    delay(io, 10)?;
    check_profile(io)?;
    acquire(io)?;
    let ctrl = io.read32(CTRL);
    let vendor = io.read_config32(0) & 0xffff;
    io.write32(STRAP, vendor);
    io.write32(CTRL, ctrl | PHY_RESET | MAC_RESET);
    // Intel expressly forbids an MMIO flush here: it can hang the device.
    if !io.delay_ms(20) {
        return Err(Error::ResetRecoveryRequired);
    }
    let vendor = io.read_config32(0) & 0xffff;
    io.write32(STRAP, vendor);
    if let Err(error) = poll(io, CTRL, MAC_RESET, 0, 100, Error::ResetTimeout) {
        // No MMIO cleanup until reset completion is known, including when
        // the poll's clock failed after the mandatory no-MMIO interval.
        return Err(if error == Error::TimerUnavailable {
            Error::ResetRecoveryRequired
        } else {
            error
        });
    }
    update(io, CTRL, 0, 4); // reset may clear GIO_MASTER_DISABLE
    // Reset clears SWFLAG; release after confirmed completion. An uncertain
    // reset returns above without accessing the shared semaphore again.
    release(io);
    let result = finish_initialization(io);
    if result.is_err() {
        // No DMA ring has been installed or enabled by this module yet.
        io.write32(IMC, u32::MAX);
        io.write32(RCTL, 0);
        io.write32(TCTL, 8);
        update(io, CTRL, 0, 4);
        io.read32(STATUS);
    }
    result
}

fn finish_initialization(io: &mut impl Io) -> Result<Initialized, Error> {
    poll(
        io,
        STATUS,
        0x200,
        0x200,
        150,
        Error::NvmConfigurationTimeout,
    )?;
    update(io, STATUS, 0x600, 0); // LAN_INIT_DONE and PHY reset asserted.
    delay(io, 10)?;
    check_profile(io)?;
    acquire(io)?;
    let configured = configure_phy(io);
    release(io);
    let phy_id = configured?;
    initialize_mac_bits(io);

    let lo = io.read32(0x5400);
    let hi = io.read32(0x5404);
    let mac = [
        lo as u8,
        (lo >> 8) as u8,
        (lo >> 16) as u8,
        (lo >> 24) as u8,
        hi as u8,
        (hi >> 8) as u8,
    ];
    if hi & 0x8000_0000 == 0 || mac[0] & 1 != 0 || mac == [0; 6] {
        return Err(Error::InvalidMac);
    }
    // RAR0 is the host address. Other shared PCH RARs belong to firmware and
    // are not generalized from the emulated 82540's address-table geometry.
    for index in 0..32 {
        io.write32(0x5200 + index * 4, 0);
    }
    // Autonegotiation is bounded; unplugged cable is a successful idle device.
    let mut link_up = false;
    for _ in 0..50 {
        if refresh_link(io)? {
            link_up = true;
            break;
        }
        delay(io, 100)?;
    }
    Ok(Initialized {
        mac,
        phy_id,
        link_up,
    })
}

fn configure_phy(io: &mut impl Io) -> Result<u32, Error> {
    let id = check_phy_profile(io)?;
    phy_update(io, 769, 17, 0x10, 0)?; // host wakeup after LCD reset
    phy_update(io, 769, 16, 0, 0x400)?; // slow MDIO access
    phy_update(io, 0, 22, 3 << 10, 0x8000)?; // CRS on Tx; disable downshift
    phy_update(io, 0, 18, 0x600, 0x400)?; // automatic MDI/MDIX
    phy_update(io, 772, 20, 0x6000, 0)?; // EEE disabled
    // IEEE advertisement selector, no 10/100 and no pause advertisement.
    phy(io, 0, 4, Some(1))?;
    // Preserve unrelated test bits; choose automatic master/slave, 1000/full.
    phy_update(io, 0, 9, 0x1300, 0x0200)?;
    phy_update(io, 0, 0, 0x7c00, 0x1200)?; // auto-negotiation + restart
    update(
        io,
        CTRL,
        (1 << 11) | (1 << 12) | (1 << 27) | (1 << 28),
        1 << 6,
    );
    Ok(id)
}

fn initialize_mac_bits(io: &mut impl Io) {
    update(io, 0x3004, 0, 0x50000); // analog bias after reset
    io.write32(IMC, u32::MAX);
    io.read32(0xc0);
    update(io, CTRL_EXT, 0, (1 << 22) | (1 << 20) | (1 << 17));
    for reg in [0x3828, 0x3928] {
        update(io, reg, 0x003f_003f, (1 << 22) | 0x0101_001f);
    }
    update(io, 0x3840, 0, (1 << 23) | (1 << 24) | (1 << 26) | (1 << 27));
    update(io, 0x3940, 0, (1 << 28) | (1 << 24) | (1 << 26) | (1 << 30));
    update(io, 0x5008, 0, 0xc0); // disable NFS filters
    update(io, 0x100c, 0, 0x10000); // packet-buffer ECC
    update(io, CTRL, 0, 0x80000); // memory error handling
    update(io, 0x5b00, 0x3f, 0); // DMA snooping enabled
    update(io, 0x24, 7, 7); // 8us beacon duration
    // SPT TX DMA corruption errata, Intel specification update 1.5.4.5.
    update(io, 0xf28, 0, 0x10000);
    update(io, 0x3840, 0x3000_0000, 0x2000_0000);
    update(io, 0x5bbc, 0, 0x2000); // disable MULR fix
    io.write32(0x410, 0x0060_2008); // TIPG 8/8/6, gigabit full duplex
    // Flow control remains disabled, consistent with PHY advertisement.
    io.write32(0x2160, 0);
    io.write32(0x2168, 0);
}

fn configure_gigabit_link(io: &mut impl Io) -> Result<(), Error> {
    acquire(io)?;
    let result = (|| {
        phy(io, 0, 16, Some(0xb20c))?; // EMI RX configuration address
        phy(io, 0, 17, Some(1))?;
        phy_update(io, 772, 28, 0x7ff, 0xfa)?;
        phy_update(io, 770, 17, 0, 0x200)?; // K1 clock request
        let gap = phy(io, 776, 20, None)?;
        if (gap >> 2) & 0x3ff < 0x18 {
            phy(io, 776, 20, Some((gap & !0xffc) | (0x18 << 2)))?;
        }
        phy_update(io, 772, 20, 0x6000, 0)?;
        // Kumeran K0s minimum residency. The reference requires >=2us after
        // each indirect transaction; this interface conservatively waits 1ms.
        io.write32(0x34, (0x1e << 16) | 0x20_0000);
        io.read32(STATUS);
        delay(io, 1)?;
        let k0s = io.read32(0x34) as u16;
        io.write32(0x34, (0x1e << 16) | u32::from((k0s & !0x70) | 0x10));
        io.read32(STATUS);
        delay(io, 1)?;
        Ok(())
    })();
    release(io);
    result?;
    // SPT only: mirror analog K1-off configuration, rather than assuming the
    // old 82540 has the same MAC/PHY clocking behavior.
    let k1 = io.read32(0xf18) & 0x8000_0000;
    update(io, 0x10, 0x8000_0000, k1);
    configure_platform_latency(io)
}

fn configure_platform_latency(io: &mut impl Io) -> Result<(), Error> {
    // FreeBSD e1000_platform_pm_pch_lpt for a 1522-byte maximum wire frame,
    // specialized to the only admitted link speed, 1000Mb/s.
    let rxa = io.read32(0x1000) & 0xffff;
    if !(4..=32).contains(&rxa) {
        return Err(Error::InvalidPacketBuffer);
    }
    let mut latency_ns = u64::from(rxa * 1024 - 2 * 1522) * 8;
    let mut value = latency_ns;
    let mut scale = 0;
    while value > 1023 {
        scale += 1;
        value = value.div_ceil(32);
    }
    if scale > 5 {
        return Err(Error::InvalidLatencyConfiguration);
    }
    let mut encoded = (scale << 10) | value as u32;
    let cap = io.read_config32(0xa8);
    let platform = (cap & 0xffff).max(cap >> 16);
    if platform & !0x1fff != 0 || ((platform >> 10) & 7) > 5 {
        return Err(Error::InvalidLatencyConfiguration);
    }
    if encoded > platform {
        encoded = platform;
        latency_ns = u64::from(platform & 1023) << (((platform >> 10) & 7) * 5);
    }
    let high_water = if latency_ns == 0 {
        0
    } else {
        i64::from(rxa) - (latency_ns * 1_000_000 / 8 / 1_000_000_000) as i64
    };
    if !(0..=31).contains(&high_water) {
        return Err(Error::InvalidLatencyConfiguration);
    }
    io.write32(
        0xf8,
        (1 << 30) | (1 << 31) | (1 << 15) | encoded | (encoded << 16),
    );
    update(io, 0xf4, 31, high_water as u32);
    update(io, 0xf0, 0, 0x1001);
    Ok(())
}

fn configure_link_down_latency(io: &mut impl Io) {
    // Intel e1000_platform_pm_pch_lpt(link=false): SEND is set, neither
    // snoop/no-snoop requirement is asserted, both encoded latencies are zero.
    // OBFF remains enabled with a zero high-water mark and unmasked interrupts.
    io.write32(0xf8, 1 << 30);
    update(io, 0xf4, 31, 0);
    update(io, 0xf0, 0, 0x1001);
}

/// Refresh a carrier transition without resetting hardware or modifying rings.
/// The caller serializes this with transmit/receive and records the returned
/// carrier state. A down result does not return ownership of any DMA memory.
/// Retry an unresolved up transition; MAC link alone can be stale during AN.
pub fn refresh_link(io: &mut impl Io) -> Result<bool, Error> {
    let status = io.read32(STATUS);
    if status & 2 == 0 {
        configure_link_down_latency(io);
        return Ok(false);
    }
    acquire(io)?;
    let resolved: Result<bool, Error> = (|| {
        // Restart is self-clearing. Read BMSR twice because link status is
        // latch-low (Intel e1000_phy_has_link_generic). Require current link
        // and AN completion before applying the negotiated-speed workarounds.
        let control = phy(io, 0, 0, None)?;
        phy(io, 0, 1, None)?;
        let status = phy(io, 0, 1, None)?;
        Ok(control & 0x200 == 0 && status & 0x24 == 0x24)
    })();
    release(io);
    if !resolved? {
        configure_link_down_latency(io);
        return Ok(false);
    }
    // Only judge speed after PHY negotiation resolves: MAC speed can retain
    // the previous link during restart. Check before speed-specific writes.
    let status = io.read32(STATUS);
    if status & 2 == 0 {
        configure_link_down_latency(io);
        return Ok(false);
    }
    if status & 0xc3 != 0x83 {
        return Err(Error::UnsupportedLink);
    }
    configure_gigabit_link(io)?;
    // Carrier can change while the MDIO workarounds run. Do not publish the
    // earlier up observation if it has already ceased to hold.
    let status = io.read32(STATUS);
    if status & 2 == 0 {
        configure_link_down_latency(io);
        return Ok(false);
    }
    if status & 0xc3 != 0x83 {
        return Err(Error::UnsupportedLink);
    }
    Ok(true)
}

/// Program queue 0 only. Memory is caller-owned, pinned, zeroed, DMA-addressable
/// and coherent; RX descriptors must already contain valid 2048-byte buffers.
/// Counts must be multiples of eight (128-byte lengths). No DMA starts here.
pub fn configure_legacy_rings(
    io: &mut impl Io,
    tx: u64,
    tx_count: u16,
    rx: u64,
    rx_count: u16,
) -> Result<(), Error> {
    for (address, count) in [(tx, tx_count), (rx, rx_count)] {
        if address == 0
            || address & 127 != 0
            || count < 8
            || count % 8 != 0
            || count > 4096
            || address.checked_add(u64::from(count) * 16).is_none()
        {
            return Err(Error::InvalidRing);
        }
    }
    let tx_end = tx + u64::from(tx_count) * 16;
    let rx_end = rx + u64::from(rx_count) * 16;
    if tx < rx_end && rx < tx_end {
        return Err(Error::InvalidRing);
    }
    if io.read32(RCTL) & 2 != 0 || io.read32(TCTL) & 2 != 0 {
        return Err(Error::InheritedDescriptors);
    }
    // Extended RX writeback would overwrite the legacy buffer-address word.
    // RCTL is programmed from zero at activation (DTYP=0); force legacy RFCTL
    // explicitly as well, rather than relying on an inherited reset default.
    update(io, 0x5008, 1 << 15, 0);
    if io.read32(0x5008) & (1 << 15) != 0 {
        return Err(Error::InvalidRing);
    }
    for (base, address, count) in [(0x3800, tx, tx_count), (0x2800, rx, rx_count)] {
        io.write32(base, address as u32);
        io.write32(base + 4, (address >> 32) as u32);
        io.write32(base + 8, u32::from(count) * 16);
        io.write32(base + 0x10, 0);
        io.write32(
            base + 0x18,
            if base == 0x2800 {
                u32::from(count) - 1
            } else {
                0
            },
        );
    }
    io.write32(0x5000, 0); // no RX checksum offload
    io.read32(STATUS);
    Ok(())
}

/// Caller must have installed valid rings and retained their DMA allocations.
/// PCI bus mastering can remain disabled until this succeeds. Never call this
/// to recover a previous active generation; that requires qualified quiescence.
pub fn enable_legacy(io: &mut impl Io) -> Result<(), Error> {
    if !refresh_link(io)? {
        return Err(Error::LinkDown);
    }
    update(io, CTRL, 4, 0);
    // No long packets, loopback, promiscuous receive, or VLAN filtering.
    io.write32(RCTL, 2 | (1 << 15) | (1 << 26)); // broadcast, strip FCS, 2K
    io.write32(TCTL, 2 | 8 | (15 << 4) | (64 << 12) | (1 << 24) | (1 << 28));
    io.read32(STATUS);
    Ok(())
}

#[cfg(test)]
mod tests {
    extern crate std;
    use super::*;
    use std::collections::BTreeMap;
    use std::vec::Vec;

    #[derive(Debug, PartialEq, Eq)]
    enum Op {
        Read(u32),
        Write(u32, u32),
        Config(u8),
        Delay(u32),
    }

    struct Fake {
        registers: BTreeMap<u32, u32>,
        phy: BTreeMap<(u8, u16, u8), u16>,
        page: u16,
        trace: Vec<Op>,
        pci_id: u32,
        pending: bool,
        mdio_fault: u32,
        timer_failure: Option<u32>,
        post_reset_timer_failure: bool,
        reset_finishes: bool,
        nvm_finishes: bool,
        negotiation_waits: Option<u32>,
        negotiation_pending: bool,
        bmsr_latched: Option<u16>,
    }

    impl Fake {
        fn new() -> Self {
            let mut registers = BTreeMap::new();
            registers.insert(FWSM, 0x40);
            registers.insert(0x5400, 0x33221102);
            registers.insert(0x5404, 0x80005544);
            registers.insert(0x1000, 26);
            let mut phy = BTreeMap::new();
            phy.insert((2, 0, 2), (PHY_ID >> 16) as u16);
            phy.insert((2, 0, 3), PHY_ID as u16 | 1);
            // Nonzero inherited configuration exercises masked writes rather
            // than making every read/modify/write pass against zero.
            phy.insert((2, 0, 22), 0x0c15);
            phy.insert((2, 0, 18), 0x0225);
            phy.insert((2, 0, 9), 0x1901);
            phy.insert((1, 772, 20), 0x6041);
            phy.insert((1, 772, 28), 0xa555);
            phy.insert((1, 776, 20), 0xa003);
            registers.insert(0xf4, 0x5a00_0017);
            registers.insert(0xf0, 0x0055_0080);
            registers.insert(0x10, 0x8000_0140);
            registers.insert(0xf18, 0x8000_0000);
            Self {
                registers,
                phy,
                page: 0,
                trace: Vec::new(),
                pci_id: PCI_ID,
                pending: false,
                mdio_fault: 0,
                timer_failure: None,
                post_reset_timer_failure: false,
                reset_finishes: true,
                nvm_finishes: true,
                negotiation_waits: None,
                negotiation_pending: false,
                bmsr_latched: None,
            }
        }
        fn wrote_reset(&self) -> bool {
            self.trace
                .iter()
                .any(|op| matches!(op, Op::Write(CTRL, v) if v & MAC_RESET != 0))
        }
        fn enabled_dma(&self) -> bool {
            self.trace
                .iter()
                .any(|op| matches!(op, Op::Write(RCTL | TCTL, v) if v & 2 != 0))
        }
    }

    impl Io for Fake {
        fn read32(&mut self, offset: u32) -> u32 {
            self.trace.push(Op::Read(offset));
            self.registers.get(&offset).copied().unwrap_or(0)
        }
        fn write32(&mut self, offset: u32, value: u32) {
            self.trace.push(Op::Write(offset, value));
            if offset == MDIC {
                let address = ((value >> 21) & 31) as u8;
                let reg = ((value >> 16) & 31) as u8;
                let key = (address, if reg <= 15 { 0 } else { self.page }, reg);
                let mut response = value | 0x1000_0000;
                if value & 0x0400_0000 != 0 {
                    if reg == 31 && address == 1 {
                        self.page = (value as u16) >> 5;
                    } else {
                        self.phy.insert(key, value as u16);
                        if key == (2, 0, 0) && value & 0x200 != 0 {
                            self.negotiation_pending = true;
                            self.phy.insert((2, 0, 1), 0);
                            self.bmsr_latched = Some(0);
                        }
                    }
                } else {
                    let data = if key == (2, 0, 1) {
                        self.bmsr_latched
                            .take()
                            .unwrap_or_else(|| self.phy.get(&key).copied().unwrap_or(0))
                    } else {
                        self.phy.get(&key).copied().unwrap_or(0)
                    };
                    response = (response & !0xffff) | u32::from(data);
                }
                self.registers.insert(offset, response ^ self.mdio_fault);
            } else if offset == CTRL && value & MAC_RESET != 0 {
                self.registers
                    .insert(offset, if self.reset_finishes { 0 } else { value });
                if self.nvm_finishes {
                    let status = self.registers.get(&STATUS).copied().unwrap_or(0);
                    self.registers.insert(STATUS, status | 0x600);
                }
                self.registers.insert(EXTCNF_CTRL, 0);
            } else {
                self.registers.insert(offset, value);
            }
        }
        fn read_config32(&mut self, offset: u8) -> u32 {
            self.trace.push(Op::Config(offset));
            match offset {
                0 => self.pci_id,
                0xe4 if self.pending => 0x100,
                _ => 0,
            }
        }
        fn delay_ms(&mut self, ms: u32) -> bool {
            self.trace.push(Op::Delay(ms));
            if self.negotiation_pending
                && ms == 100
                && let Some(waits) = self.negotiation_waits.as_mut()
            {
                *waits = waits.saturating_sub(1);
                if *waits == 0 {
                    self.negotiation_pending = false;
                    let control = self.phy[&(2, 0, 0)] & !0x200;
                    self.phy.insert((2, 0, 0), control);
                    self.phy.insert((2, 0, 1), 0x24);
                    let status = self.registers.get(&STATUS).copied().unwrap_or(0);
                    self.registers.insert(STATUS, (status & !0xc3) | 0x83);
                }
            }
            self.timer_failure != Some(ms)
                && !(self.post_reset_timer_failure && self.wrote_reset() && ms == 1)
        }
    }

    #[test]
    fn unsupported_device_never_touches_mmio() {
        let mut io = Fake::new();
        io.pci_id = 0x100e8086;
        assert_eq!(initialize(&mut io), Err(Error::UnsupportedDevice));
        assert_eq!(io.trace, [Op::Config(0)]);
    }

    #[test]
    fn firmware_and_inherited_states_refuse_before_reset_or_dma() {
        for (reg, value, error) in [
            (FWSM, 0x8040, Error::FirmwareOwned),
            (FWSM, 0, Error::ResetBlocked),
            (FWSM, 0x440, Error::LowPowerState),
            (CTRL_EXT, 0x800, Error::LowPowerState),
            (FEXTNVM, 1 << 27, Error::SoftwarePhyConfiguration),
            (RCTL, 2, Error::InheritedDescriptors),
            (TCTL, 2, Error::InheritedDescriptors),
        ] {
            let mut io = Fake::new();
            io.registers.insert(reg, value);
            assert_eq!(initialize(&mut io), Err(error));
            assert!(!io.wrote_reset());
            assert!(!io.enabled_dma());
        }
        let mut io = Fake::new();
        io.pending = true;
        assert_eq!(initialize(&mut io), Err(Error::InheritedDescriptors));
        assert!(!io.wrote_reset());
    }

    #[test]
    fn mdio_failures_release_semaphore_without_reset() {
        for (fault, error) in [
            (0x4000_0000, Error::MdioError),
            (0x0001_0000, Error::MdioResponseMismatch),
            (0x1000_0000, Error::MdioTimeout),
        ] {
            let mut io = Fake::new();
            io.mdio_fault = fault;
            assert_eq!(initialize(&mut io), Err(error));
            assert_eq!(io.registers[&EXTCNF_CTRL] & SWFLAG, 0);
            assert!(!io.wrote_reset());
            assert!(!io.enabled_dma());
        }
    }

    #[test]
    fn wrong_phy_and_phy_low_power_refuse_before_reset() {
        let mut io = Fake::new();
        io.phy.insert((2, 0, 2), 0xffff);
        assert_eq!(initialize(&mut io), Err(Error::UnsupportedPhy));
        assert!(!io.wrote_reset());
        for key in [(1, 769, 23), (1, 779, 16)] {
            let mut io = Fake::new();
            io.phy.insert(key, 1);
            assert_eq!(initialize(&mut io), Err(Error::LowPowerState));
            assert!(!io.wrote_reset());
        }
    }

    #[test]
    fn successful_idle_init_observes_reset_no_mmio_window_and_keeps_dma_off() {
        let mut io = Fake::new();
        let ready = initialize(&mut io).unwrap();
        assert_eq!(ready.mac, [2, 0x11, 0x22, 0x33, 0x44, 0x55]);
        assert!(!ready.link_up);
        assert!(!io.enabled_dma());
        assert_eq!(io.registers[&EXTCNF_CTRL] & SWFLAG, 0);
        assert_eq!(io.registers[&CTRL] & 4, 4);
        let reset = io
            .trace
            .iter()
            .position(|op| matches!(op, Op::Write(CTRL,v) if v & MAC_RESET != 0))
            .unwrap();
        assert_eq!(
            &io.trace[reset + 1..reset + 4],
            &[Op::Delay(20), Op::Config(0), Op::Write(STRAP, 0x8086)]
        );
    }

    #[test]
    fn reset_delay_failure_does_not_touch_mmio_again() {
        let mut io = Fake::new();
        io.timer_failure = Some(20);
        assert_eq!(initialize(&mut io), Err(Error::ResetRecoveryRequired));
        assert_eq!(io.trace.last(), Some(&Op::Delay(20)));
        assert!(!io.enabled_dma());
    }

    #[test]
    fn reset_and_nvm_timeouts_never_enable_dma() {
        let mut io = Fake::new();
        io.reset_finishes = false;
        assert_eq!(initialize(&mut io), Err(Error::ResetTimeout));
        assert!(!io.enabled_dma());
        let mut io = Fake::new();
        io.nvm_finishes = false;
        assert_eq!(initialize(&mut io), Err(Error::NvmConfigurationTimeout));
        assert!(!io.enabled_dma());
    }

    #[test]
    fn clock_failure_during_reset_poll_requires_no_more_mmio() {
        let mut io = Fake::new();
        io.reset_finishes = false;
        io.post_reset_timer_failure = true;
        assert_eq!(initialize(&mut io), Err(Error::ResetRecoveryRequired));
        assert_eq!(io.trace.last(), Some(&Op::Delay(1)));
        let reset = io
            .trace
            .iter()
            .position(|op| matches!(op, Op::Write(CTRL, v) if v & MAC_RESET != 0))
            .unwrap();
        assert_eq!(
            &io.trace[reset + 1..],
            &[
                Op::Delay(20),
                Op::Config(0),
                Op::Write(STRAP, 0x8086),
                Op::Read(CTRL),
                Op::Delay(1)
            ]
        );
    }

    #[test]
    fn legacy_rx_format_is_selected_even_if_extended_mode_was_set() {
        let mut io = Fake::new();
        io.registers.insert(0x5008, 0x8000 | 0xc0);
        configure_legacy_rings(&mut io, 0x100000, 16, 0x200000, 32).unwrap();
        assert_eq!(io.registers[&0x5008], 0xc0);
        assert!(!io.enabled_dma());
    }

    #[test]
    fn rings_are_validated_before_any_register_mutation() {
        for (tx, nt, rx, nr) in [
            (0, 16, 0x2000, 32),
            (0x1001, 16, 0x2000, 32),
            (0x1000, 7, 0x2000, 32),
            (0x1000, 16, 0x1000, 32),
            (0x1000, 16, 0x2000, 4097),
            (u64::MAX - 127, 16, 0x2000, 32),
        ] {
            let mut io = Fake::new();
            assert_eq!(
                configure_legacy_rings(&mut io, tx, nt, rx, nr),
                Err(Error::InvalidRing)
            );
            assert!(io.trace.is_empty());
        }
    }

    #[test]
    fn separate_ring_counts_and_high_addresses_are_preserved() {
        let mut io = Fake::new();
        configure_legacy_rings(&mut io, 0x1_0000_1000, 16, 0x2_0000_2000, 32).unwrap();
        assert_eq!(io.registers[&0x3804], 1);
        assert_eq!(io.registers[&0x2804], 2);
        assert_eq!(io.registers[&0x3808], 256);
        assert_eq!(io.registers[&0x2808], 512);
        assert_eq!(io.registers[&0x2818], 31);
        assert!(!io.enabled_dma());
    }

    #[test]
    fn unsupported_link_never_enables_dma() {
        for (status, error) in [
            (0, Error::LinkDown),
            (0x43, Error::UnsupportedLink),
            (0x82, Error::UnsupportedLink),
        ] {
            let mut io = Fake::new();
            io.registers.insert(STATUS, status);
            io.phy.insert((2, 0, 0), 0x1000);
            io.phy.insert((2, 0, 1), 0x24);
            assert_eq!(enable_legacy(&mut io), Err(error));
            assert!(!io.enabled_dma());
        }
    }

    #[test]
    fn existing_semaphore_owner_is_not_cleared() {
        let mut io = Fake::new();
        io.registers.insert(EXTCNF_CTRL, SWFLAG);
        assert_eq!(initialize(&mut io), Err(Error::SemaphoreBusy));
        assert_eq!(io.registers[&EXTCNF_CTRL], SWFLAG);
        assert!(!io.trace.iter().any(|op| matches!(op, Op::Write(_, _))));
    }

    #[test]
    fn gigabit_path_applies_errata_before_enabling_engines() {
        let mut io = Fake::new();
        io.negotiation_waits = Some(2);
        io.registers.insert(STATUS, 0x83);
        let ready = initialize(&mut io).unwrap();
        assert!(ready.link_up);
        assert!(!io.enabled_dma());
        assert_eq!(io.registers[&CTRL] & 4, 4);
        assert_eq!(io.registers[&0xf28] & 0x10000, 0x10000);
        assert_eq!(io.registers[&0x3840] & 0x3000_0000, 0x2000_0000);
        configure_legacy_rings(&mut io, 0x1000, 16, 0x2000, 32).unwrap();
        enable_legacy(&mut io).unwrap();
        assert!(io.enabled_dma());
        assert_eq!(io.registers[&CTRL] & 4, 0);
        assert_eq!(io.phy[&(2, 0, 4)], 1);
        assert_eq!(io.phy[&(2, 0, 9)] & 0x300, 0x200);
        assert_eq!(io.phy[&(1, 772, 20)] & 0x6000, 0);
        assert_eq!(io.phy[&(2, 0, 22)], 0x8015);
        assert_eq!(io.phy[&(2, 0, 18)], 0x0425);
        assert_eq!(io.phy[&(2, 0, 9)], 0x0a01);
        assert_eq!(io.phy[&(1, 772, 20)], 0x41);
        assert_eq!(io.phy[&(1, 772, 28)], 0xa0fa);
        assert_eq!(io.phy[&(1, 776, 20)], 0xa063);
        assert_eq!(
            io.trace.iter().filter(|op| **op == Op::Delay(100)).count(),
            2
        );
    }

    #[test]
    fn carrier_down_programs_source_defined_latency_without_mdio_or_ring_writes() {
        let mut io = Fake::new();
        io.registers.insert(RCTL, 2 | (1 << 15) | (1 << 26));
        io.registers.insert(TCTL, 0x1104_00fa);
        io.registers.insert(0xf8, 0xcabc_8def);
        let before_rx = io.registers[&RCTL];
        let before_tx = io.registers[&TCTL];
        assert_eq!(refresh_link(&mut io), Ok(false));
        // Golden literal sequence from platform_pm(link=false), preserving
        // fields outside SVT.OFF_HWM and SVCR.OFF_EN/OFF_MASKINT.
        assert_eq!(
            io.trace,
            [
                Op::Read(STATUS),
                Op::Write(0xf8, 0x4000_0000),
                Op::Read(0xf4),
                Op::Write(0xf4, 0x5a00_0000),
                Op::Read(0xf0),
                Op::Write(0xf0, 0x0055_1081),
            ]
        );
        assert_eq!(io.registers[&RCTL], before_rx);
        assert_eq!(io.registers[&TCTL], before_tx);
    }

    #[test]
    fn stale_mac_link_does_not_admit_restart_or_incomplete_phy_negotiation() {
        for (mac, control, phy_status) in [
            (0x83, 0x1200, 0x24),
            (0x43, 0x1200, 0x24),
            (0x43, 0x1000, 4),
            (0x83, 0x1000, 4),
            (0x83, 0x1000, 0x20),
        ] {
            let mut io = Fake::new();
            io.registers.insert(STATUS, mac);
            io.phy.insert((2, 0, 0), control);
            io.phy.insert((2, 0, 1), phy_status);
            assert_eq!(refresh_link(&mut io), Ok(false));
            assert_eq!(io.registers[&0xf8], 0x4000_0000);
            assert_eq!(io.phy[&(1, 772, 28)], 0xa555);
            assert!(!io.enabled_dma());
            assert!(!io.wrote_reset());
        }
    }

    #[test]
    fn carrier_return_replays_phy_clock_and_latency_without_ring_reconfiguration() {
        let mut io = Fake::new();
        assert_eq!(refresh_link(&mut io), Ok(false));
        io.trace.clear();
        io.registers.insert(STATUS, 0x83);
        io.registers.insert(0xf18, 0); // successor link sees K1-off disabled
        io.phy.insert((2, 0, 0), 0x1000);
        io.phy.insert((2, 0, 1), 0x24);
        io.bmsr_latched = Some(0); // first BMSR read retains prior link loss
        assert_eq!(refresh_link(&mut io), Ok(true));
        assert_eq!(io.phy[&(1, 772, 28)], 0xa0fa);
        assert_eq!(io.phy[&(1, 776, 20)], 0xa063);
        assert_eq!(io.registers[&0x10], 0x140);
        assert_eq!(io.registers[&0xf8], 0xc000_8000);
        assert_eq!(io.registers[&0xf4], 0x5a00_0000);
        assert_eq!(io.registers[&0xf0], 0x0055_1081);
        assert_eq!(
            io.trace
                .iter()
                .filter(|op| matches!(op,
            Op::Write(MDIC, command) if command & 0x0bff_0000 == 0x0841_0000))
                .count(),
            2
        );
        assert!(!io.trace.iter().any(|op| matches!(op,
            Op::Write(reg, _) if *reg == RCTL || *reg == TCTL || *reg == CTRL
                || (0x2800..=0x2818).contains(reg) || (0x3800..=0x3818).contains(reg))));
    }
}
