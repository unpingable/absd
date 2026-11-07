/*
 * Copyright (c) 2019, 2020, 2023-2026
 *	Kevin Lo <kevlo@openbsd.org>
 *
 * Copyright (c) 2019, 2020, 2025, 2026
 *	Kevin Lo <kevlo@openbsd.org>
 *
 * Permission to use, copy, modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

//! Bounded Realtek RTL8125B (10ec:8125, TXCFG revision 0x641) register logic.
//!
//! Register offsets, bit values and sequences adapted from OpenBSD
//! `sys/dev/pci/if_rge.c` v1.48 and `if_rgereg.h` v1.20 (the two notices
//! above). Only the 8125B (`MAC_R25B`) path is kept. No firmware is loaded:
//! the MAC MCU and PHY RAM-code patch tables of `rtl8125b-2.fw` are never
//! applied (docs/RTL8125.md). The caller owns PCI admission, the uncached
//! BAR mapping, DMA memory and bus mastering.

pub const IDR0: u32 = 0x00;
pub const IDR4: u32 = 0x04;
pub const CMD: u32 = 0x37;
pub const IMR: u32 = 0x38;
pub const ISR: u32 = 0x3c;
pub const TXCFG: u32 = 0x40;
pub const RXCFG: u32 = 0x44;
pub const PHYSTAT: u32 = 0x6c;
pub const MACOCP: u32 = 0xb0;
pub const PHYOCP: u32 = 0xb8;
pub const ADDR0: u32 = 0x19e0;
pub const ADDR1: u32 = 0x19e4;
const EECMD: u32 = 0x50;
const CFG2: u32 = 0x53;
const CFG5: u32 = 0x56;
const TIMERINT0: u32 = 0x58;
const TIMERINT1: u32 = 0x5c;
const PMCH: u32 = 0x6f;
const EPHYAR: u32 = 0x80;
const TIMERINT2: u32 = 0x8c;
const TWICMD: u32 = 0xd2;
const MCUCMD: u32 = 0xd3;
const IM: u32 = 0xe2;
const PPSW: u32 = 0xf2;
const TIMERINT3: u32 = 0xf4;
const REG_F1: u32 = 0xf1;

const CMD_STOPREQ: u8 = 0x80;
const EECMD_WRITECFG: u8 = 0xc0;
const MCUCMD_FIFOS_EMPTY: u8 = 0x30;
const MCUCMD_IS_OOB: u8 = 0x80;
const EPHYAR_BUSY: u32 = 0x8000_0000;
/// RXCFG ALLPHYS|INDIV|MULTI|BROAD|RUNT|ERRPKT.
const RXCFG_ACCEPT: u32 = 0x3f;

/// ISR bits (rge `RGE_ISR_*`). The NIC path polls ISR with IMR clear.
pub const ISR_RX_DESC_UNAVAIL: u32 = 0x0000_0010;
pub const ISR_RX_FIFO_OFLOW: u32 = 0x0000_0040;
pub const ISR_SYSTEM_ERR: u32 = 0x0000_8000;

pub const CMD_TXENB: u8 = 0x04;
pub const CMD_RXENB: u8 = 0x08;
pub const CMD_RESET: u8 = 0x10;

const TXCFG_HWREV: u32 = 0x7cf0_0000;
const HWREV_8125B: u32 = 0x6410_0000;
const OCP_BUSY: u32 = 0x8000_0000;
/// Register reads allowed while an OCP access is in flight. rge waits up to
/// 20000 x 1 us; one non-posted PCIe read takes longer than a microsecond,
/// so a read count bounds the wait at least as long.
const OCP_POLLS: u32 = 20_000;

pub const PHYSTAT_FDX: u16 = 0x0001;
pub const PHYSTAT_LINK: u16 = 0x0002;
pub const PHYSTAT_10: u16 = 0x0004;
pub const PHYSTAT_100: u16 = 0x0008;
pub const PHYSTAT_1000: u16 = 0x0010;
pub const PHYSTAT_2500: u16 = 0x0400;

/// MII registers of the internal PHY, reached through PHY OCP.
pub const MII_BMCR: u8 = 0;
pub const MII_BMSR: u8 = 1;
pub const MII_PHYIDR1: u8 = 2;
pub const MII_PHYIDR2: u8 = 3;
pub const MII_ANAR: u8 = 4;
pub const MII_100T2CR: u8 = 9;

const BMCR_RESET: u16 = 0x8000;
const BMCR_AUTOEN: u16 = 0x1000;
const BMCR_STARTNEG: u16 = 0x0200;
/// ANAR 10/100 abilities. rge also sets the pause bits (0x0c00); this
/// backend does not (review F3): the MAC honours received PAUSE whenever
/// negotiation resolves flow control on (PHYSTAT 0x0020/0x0040), and a
/// stream of PAUSE frames then stalls transmission (corrective runs x1-x5:
/// with pause unadvertised, PHYSTAT shows no flow bits and 1000/1000
/// frames went out during the storm). rge has no MAC control that ignores
/// PAUSE independently of the negotiation.
const ANAR_ABILITIES: u16 = 0x01e0;
/// The ANAR pause bits (symmetric and asymmetric), never advertised.
pub const ANAR_PAUSE: u16 = 0x0c00;
/// GTCR 1000BASE-T full and half duplex.
const GTCR_1000: u16 = 0x0300;
/// PHY OCP 0xa5d4 bit for 2500BASE-T full duplex.
pub const ADV_2500: u16 = 0x0080;
const PHY_ADV_2500: u16 = 0xa5d4;
/// PHY RAM-code version rge's 8125B patch installs (RGE_MAC_R25B_RCODE_VER).
pub const PATCHED_RCODE: u16 = 0x0b99;

/// rge `mac_r25b_ephy`: fixed PCIe PHY settings, a driver constant.
const EPHY_8125B: [(u16, u16); 10] = [
    (0x000b, 0xa908),
    (0x001e, 0x20eb),
    (0x0022, 0x0023),
    (0x0002, 0x60c2),
    (0x0029, 0xff00),
    (0x004b, 0xa908),
    (0x005e, 0x28eb),
    (0x0062, 0x0023),
    (0x0042, 0x60c2),
    (0x0069, 0xff00),
];

/// Implementations use ordered volatile MMIO and serialize this device.
/// A successful delay must measure actual time, not a guessed loop count.
pub trait Io {
    fn read8(&mut self, offset: u32) -> u8;
    fn read16(&mut self, offset: u32) -> u16;
    fn read32(&mut self, offset: u32) -> u32;
    fn write8(&mut self, offset: u32, value: u8);
    fn write16(&mut self, offset: u32, value: u16);
    fn write32(&mut self, offset: u32, value: u32);
    fn delay_ms(&mut self, milliseconds: u32) -> bool;
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    /// TXCFG names a revision other than the 8125B; the value is kept.
    UnsupportedRevision(u32),
    /// The register window reads as all ones: the function is not decoding.
    NotDecoding,
    PhyOcpTimeout,
    InvalidMac,
    EphyTimeout,
    TimerUnavailable,
    /// The soft reset bit did not clear within rge's bound. No retry.
    ResetTimeout,
    /// The PHY reset bit did not clear within rge's bound.
    PhyResetTimeout,
    /// A ring base not on rge's 256-byte boundary.
    InvalidRing,
    /// TX or RX enable still read set after the stop sequence.
    StillEnabled,
    /// A register read all ones (OCP, PHY or MMIO): the function stopped
    /// decoding or vanished. Never carrier (review F6, Codex 3).
    DeviceGone,
    /// After a reset and one retry the chip did not report both FIFOs empty
    /// and the idle indication (review F4, re-review 1). Neither report is
    /// proof that outstanding bus transactions have drained; their absence
    /// is enough to refuse.
    StopUnconfirmed,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Chip {
    /// rge `MAC_R25B`.
    Rtl8125b,
}

/// The chip from TXCFG. Only the 8125B is admitted.
pub fn chip(txcfg: u32) -> Result<Chip, Error> {
    match txcfg & TXCFG_HWREV {
        HWREV_8125B => Ok(Chip::Rtl8125b),
        other => Err(Error::UnsupportedRevision(other)),
    }
}

/// The 12-bit "XID" (TXCFG bits 30:20 as Linux and the vendor print it).
pub fn xid(txcfg: u32) -> u16 {
    ((txcfg >> 20) & 0xfcf) as u16
}

/// Six address bytes from two little-endian register reads.
pub fn mac_from(low: u32, high: u32) -> [u8; 6] {
    let [a, b, c, d] = low.to_le_bytes();
    let [e, f, _, _] = high.to_le_bytes();
    [a, b, c, d, e, f]
}

/// A usable station address: not zero, not all ones, not group.
pub fn valid_mac(mac: [u8; 6]) -> bool {
    mac != [0; 6] && mac != [0xff; 6] && mac[0] & 1 == 0
}

/// PHY OCP address of internal-PHY MII register `reg` (rge_read_phy with
/// addr 0): `(0xa40 + reg / 8) << 4` plus `(reg % 8) * 2`.
pub fn mii_ocp(reg: u8) -> u16 {
    ((0x0a40 + u16::from(reg) / 8) << 4) + (u16::from(reg) % 8) * 2
}

fn ocp_address(reg: u16) -> u32 {
    u32::from(reg >> 1) << 16
}

pub fn read_mac_ocp(io: &mut impl Io, reg: u16) -> u16 {
    io.write32(MACOCP, ocp_address(reg));
    io.read32(MACOCP) as u16
}

pub fn write_mac_ocp(io: &mut impl Io, reg: u16, value: u16) {
    io.write32(MACOCP, ocp_address(reg) | u32::from(value) | OCP_BUSY);
}

/// A PHY OCP read: the busy flag is set by the chip when data is valid.
/// All ones is a vanished function (its busy bit is set too), never data.
pub fn read_phy_ocp(io: &mut impl Io, reg: u16) -> Result<u16, Error> {
    io.write32(PHYOCP, ocp_address(reg));
    for _ in 0..OCP_POLLS {
        let value = io.read32(PHYOCP);
        if value == u32::MAX {
            return Err(Error::DeviceGone);
        }
        if value & OCP_BUSY != 0 {
            return Ok(value as u16);
        }
    }
    Err(Error::PhyOcpTimeout)
}

/// A PHY OCP write: the busy flag clears when the chip has taken it.
pub fn write_phy_ocp(io: &mut impl Io, reg: u16, value: u16) -> Result<(), Error> {
    io.write32(PHYOCP, ocp_address(reg) | u32::from(value) | OCP_BUSY);
    for _ in 0..OCP_POLLS {
        match io.read32(PHYOCP) {
            u32::MAX => return Err(Error::DeviceGone),
            word if word & OCP_BUSY == 0 => return Ok(()),
            _ => {}
        }
    }
    Err(Error::PhyOcpTimeout)
}

pub fn read_mii(io: &mut impl Io, reg: u8) -> Result<u16, Error> {
    read_phy_ocp(io, mii_ocp(reg))
}

pub fn write_mii(io: &mut impl Io, reg: u8, value: u16) -> Result<(), Error> {
    write_phy_ocp(io, mii_ocp(reg), value)
}

fn phy_update(io: &mut impl Io, reg: u16, clear: u16, set: u16) -> Result<(), Error> {
    let value = read_phy_ocp(io, reg)?;
    write_phy_ocp(io, reg, (value & !clear) | set)
}

fn mac_update(io: &mut impl Io, reg: u16, clear: u16, set: u16) {
    let value = read_mac_ocp(io, reg);
    write_mac_ocp(io, reg, (value & !clear) | set);
}

fn update8(io: &mut impl Io, reg: u32, clear: u8, set: u8) {
    let value = io.read8(reg);
    io.write8(reg, (value & !clear) | set);
}

fn delay(io: &mut impl Io, ms: u32) -> Result<(), Error> {
    if io.delay_ms(ms) {
        Ok(())
    } else {
        Err(Error::TimerUnavailable)
    }
}

/// Calls `done` up to `attempts` times, a millisecond apart. rge's
/// microsecond waits become millisecond waits, so every bound is at least
/// rge's. Returns whether `done` held; a stalled timer is an error.
fn poll<I: Io>(
    io: &mut I,
    attempts: u32,
    mut done: impl FnMut(&mut I) -> Result<bool, Error>,
) -> Result<bool, Error> {
    for _ in 0..attempts {
        if done(io)? {
            return Ok(true);
        }
        delay(io, 1)?;
    }
    Ok(false)
}

fn write_ephy(io: &mut impl Io, reg: u16, value: u16) -> Result<(), Error> {
    io.write32(
        EPHYAR,
        (u32::from(reg) & 0x7f) << 16 | EPHYAR_BUSY | u32::from(value),
    );
    for _ in 0..OCP_POLLS {
        match io.read32(EPHYAR) {
            u32::MAX => return Err(Error::DeviceGone),
            word if word & EPHYAR_BUSY == 0 => return Ok(()),
            _ => {}
        }
    }
    Err(Error::EphyTimeout)
}

/// What a bounded wait that rge does not treat as fatal actually saw.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Waits {
    /// MCUCMD reported both FIFOs empty after STOPREQ.
    pub fifos_empty: bool,
    /// IM read 0x0103 (the 8125B's idle indication) after STOPREQ.
    pub idle: bool,
    /// MCUCMD as last read (0x10 RX FIFO empty, 0x20 TX FIFO empty).
    pub mcucmd: u8,
}

/// `rge_reset`: stop, drain, soft reset. RX accept bits are cleared and the
/// RXDV gate closed first; TX/RX enable are cleared before the reset bit.
/// Only the reset bit itself is fatal if it does not clear.
pub fn reset(io: &mut impl Io) -> Result<Waits, Error> {
    let rxcfg = io.read32(RXCFG);
    io.write32(RXCFG, rxcfg & !RXCFG_ACCEPT);
    update8(io, PPSW, 0, 0x08);
    update8(io, CMD, 0, CMD_STOPREQ);
    delay(io, 1)?;
    let mut mcucmd = 0;
    let fifos_empty = poll(io, 150, |io| {
        mcucmd = io.read8(MCUCMD);
        Ok(mcucmd & MCUCMD_FIFOS_EMPTY == MCUCMD_FIFOS_EMPTY)
    })?;
    let idle = poll(io, 150, |io| Ok(io.read16(IM) & 0x0103 == 0x0103))?;
    let cmd = io.read8(CMD);
    io.write8(CMD, cmd & (CMD_TXENB | CMD_RXENB));
    io.write8(CMD, CMD_RESET);
    if !poll(io, 11, |io| Ok(io.read8(CMD) & CMD_RESET == 0))? {
        return Err(Error::ResetTimeout);
    }
    Ok(Waits {
        fifos_empty,
        idle,
        mcucmd,
    })
}

/// `rge_hw_reset` for one vector: chip interrupts masked and acknowledged,
/// timer interrupts cleared, then `reset`.
pub fn hw_reset(io: &mut impl Io) -> Result<Waits, Error> {
    io.write32(IMR, 0);
    let isr = io.read32(ISR);
    io.write32(ISR, isr);
    for timer in [TIMERINT0, TIMERINT1, TIMERINT2, TIMERINT3] {
        io.write32(timer, 0);
    }
    reset(io)
}

/// `hw_reset` whose stop request must be confirmed by the chip: both FIFOs
/// empty (MCUCMD) and the idle indication (IM 0x0103). Otherwise the reset
/// is repeated once; still unconfirmed is `StopUnconfirmed` (review F4: a
/// reset with undrained FIFOs was followed by frames landing outside their
/// offered buffers, ps-1 and corrective x3/x4; re-review 1: idle was not
/// required). rge treats both waits as non-fatal; this backend does not.
///
/// What a confirmed stop shows is limited to what the chip reports about
/// its own FIFOs and engine. It is not quiescence of the transport: a
/// posted write the chip already issued may still be in flight, and no
/// ABSD operation drains or excludes it. Callers that reuse memory say so.
pub fn settle(io: &mut impl Io) -> Result<Waits, Error> {
    let first = hw_reset(io)?;
    if first.fifos_empty && first.idle {
        return Ok(first);
    }
    let second = hw_reset(io)?;
    if second.fifos_empty && second.idle {
        Ok(second)
    } else {
        Err(Error::StopUnconfirmed)
    }
}

/// `rge_disable_aspm_clkreq` for the 8125B: CLKREQ and PME status cleared
/// under the config-write unlock.
fn disable_aspm_clkreq(io: &mut impl Io) {
    let unlock = io.read8(EECMD) & EECMD_WRITECFG != EECMD_WRITECFG;
    if unlock {
        update8(io, EECMD, 0, EECMD_WRITECFG);
    }
    update8(io, CFG2, 0x80, 0);
    update8(io, CFG5, 0x01, 0);
    if unlock {
        update8(io, EECMD, EECMD_WRITECFG, 0);
    }
}

/// What `chip_init` observed.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Init {
    pub oob_reset: Waits,
    /// TWICMD bit 9 seen during the OOB release (rge does not require it).
    pub twicmd_ready: bool,
    /// MAC OCP 0xd42c bit 8 (UPS resume) was set and was cleared.
    pub ups_resume: bool,
    /// PHY state (PHY OCP 0xa420 & 7) after power-on; rge waits for 3.
    pub phy_state: u16,
    pub hw_reset: Waits,
}

/// `rge_chipinit` for the 8125B without firmware: `rge_exit_oob`,
/// `rge_set_phy_power(1)`, `rge_hw_init` and `rge_hw_reset`. The MAC MCU
/// break-point registers are cleared as rge clears them, and then
/// `rge_mac_config_mcu`, which would load the firmware's MAC patch table,
/// is skipped. The CSI write to 0x108 is skipped (docs/RTL8125.md).
pub fn chip_init(io: &mut impl Io) -> Result<Init, Error> {
    // rge_exit_oob.
    write_mac_ocp(io, 0xc0bc, 0x00ff);
    let oob_reset = reset(io)?;
    update8(io, MCUCMD, MCUCMD_IS_OOB, 0);
    mac_update(io, 0xe8de, 0x4000, 0);
    let mut twicmd_ready = poll(io, 2, |io| Ok(io.read16(TWICMD) & 0x0200 != 0))?;
    write_mac_ocp(io, 0xc0aa, 0x07d0);
    write_mac_ocp(io, 0xc0a6, 0x01b5);
    write_mac_ocp(io, 0xc01e, 0x5555);
    twicmd_ready &= poll(io, 2, |io| Ok(io.read16(TWICMD) & 0x0200 != 0))?;
    let ups_resume = read_mac_ocp(io, 0xd42c) & 0x0100 != 0;
    if ups_resume {
        poll(io, 100, |io| Ok(read_phy_ocp(io, 0xa420)? & 7 == 2))?;
        mac_update(io, 0xd42c, 0x0100, 0);
        phy_update(io, 0xa466, 0x0001, 0)?;
        phy_update(io, 0xa468, 0x000a, 0)?;
    }
    // rge_set_phy_power(sc, 1).
    update8(io, PMCH, 0, 0xc0);
    write_mii(io, MII_BMCR, BMCR_AUTOEN)?;
    let mut phy_state = 0;
    poll(io, 100, |io| {
        phy_state = read_phy_ocp(io, 0xa420)? & 7;
        Ok(phy_state == 3)
    })?;
    // rge_hw_init.
    disable_aspm_clkreq(io);
    update8(io, REG_F1, 0x80, 0);
    mac_update(io, 0xd40a, 0x0010, 0);
    disable_aspm_clkreq(io);
    write_mac_ocp(io, 0xfc48, 0);
    for reg in (0xfc28..0xfc48).step_by(2) {
        write_mac_ocp(io, reg, 0);
    }
    delay(io, 3)?;
    write_mac_ocp(io, 0xfc26, 0);
    // Skipped: rge_mac_config_mcu (firmware MAC patch table).
    let hw_reset = settle(io)?;
    Ok(Init {
        oob_reset,
        twicmd_ready,
        ups_resume,
        phy_state,
        hw_reset,
    })
}

/// `rge_phy_config` for the 8125B without firmware: EPHY table, PHY reset
/// with every speed withdrawn, RAM-code version read, the fixed 8125B PHY
/// settings and EEE off. `rge_phy_config_mcu` (the firmware's PHY RAM-code
/// patch, applied when the version is not `PATCHED_RCODE`) is skipped.
/// Returns the PHY RAM-code version found. `tuning` = false leaves out the
/// fixed constants of `rge_phy_config_mac_r25b` (written to a PHY that may
/// expect the patched RAM code) and changes nothing else: the A/B variant of
/// coordination record #109 lane 2.
pub fn phy_config(io: &mut impl Io, tuning: bool) -> Result<u16, Error> {
    for (reg, value) in EPHY_8125B {
        write_ephy(io, reg, value)?;
    }
    delay(io, 1)?;
    let anar = read_mii(io, MII_ANAR)?;
    write_mii(io, MII_ANAR, anar & !ANAR_ABILITIES)?;
    let gtcr = read_mii(io, MII_100T2CR)?;
    write_mii(io, MII_100T2CR, gtcr & !GTCR_1000)?;
    phy_update(io, PHY_ADV_2500, ADV_2500, 0)?;
    write_mii(io, MII_BMCR, BMCR_RESET | BMCR_AUTOEN | BMCR_STARTNEG)?;
    if !poll(io, 2500, |io| Ok(read_mii(io, MII_BMCR)? & BMCR_RESET == 0))? {
        return Err(Error::PhyResetTimeout);
    }
    write_phy_ocp(io, 0xa436, 0x801e)?;
    let rcode = read_phy_ocp(io, 0xa438)?;
    // Skipped: rge_phy_config_mcu (firmware PHY RAM-code patch).
    // rge_phy_config_mac_r25b, after its patch step.
    if tuning {
        phy_update(io, 0xa442, 0, 0x0800)?;
        phy_update(io, 0xac46, 0x00f0, 0x0090)?;
        phy_update(io, 0xad30, 0x0003, 0x0001)?;
        write_phy_ocp(io, 0xb87c, 0x80f5)?;
        write_phy_ocp(io, 0xb87e, 0x760e)?;
        write_phy_ocp(io, 0xb87c, 0x8107)?;
        write_phy_ocp(io, 0xb87e, 0x360e)?;
        write_phy_ocp(io, 0xb87c, 0x8551)?;
        phy_update(io, 0xb87e, 0xff00, 0x0800)?;
        phy_update(io, 0xbf00, 0xe000, 0xa000)?;
        phy_update(io, 0xbf46, 0x0f00, 0x0300)?;
        for i in 0..10 {
            write_phy_ocp(io, 0xa436, 0x8044 + i * 6)?;
            write_phy_ocp(io, 0xa438, 0x2417)?;
        }
        phy_update(io, 0xa4ca, 0, 0x0040)?;
        phy_update(io, 0xbf84, 0xe000, 0xa000)?;
        write_phy_ocp(io, 0xa436, 0x8170)?;
        phy_update(io, 0xa438, 0x2700, 0xd800)?;
        phy_update(io, 0xa424, 0, 0x0008)?;
    }
    // The rest of rge_phy_config: EEE and advanced EEE off.
    phy_update(io, 0xa5b4, 0x8000, 0)?;
    mac_update(io, 0xe040, 0x0003, 0);
    phy_update(io, 0xa432, 0, 0x0010)?;
    phy_update(io, 0xa5d0, 0x0006, 0)?;
    phy_update(io, 0xa6d4, 0x0001, 0)?;
    phy_update(io, 0xa6d8, 0x0010, 0)?;
    phy_update(io, 0xa428, 0x0080, 0)?;
    phy_update(io, 0xa4a2, 0x0200, 0)?;
    mac_update(io, 0xe052, 0x0001, 0);
    phy_update(io, 0xa442, 0x3000, 0)?;
    phy_update(io, 0xa430, 0x8000, 0)?;
    Ok(rcode)
}

/// The advertisement this backend programs: `rge_ifmedia_upd` for
/// IFM_AUTO on the 8125B. Every value is written, none inherited.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Advertised {
    pub anar: u16,
    pub gtcr: u16,
    pub adv_2500: u16,
}

/// Gigabit Lite off, 10/100/1000/2500 advertised without pause (see
/// `ANAR_ABILITIES`), negotiation restarted.
/// Returns the three advertisement registers as read back.
pub fn advertise_all(io: &mut impl Io) -> Result<Advertised, Error> {
    phy_update(io, 0xa428, 0x0200, 0)?;
    phy_update(io, 0xa5ea, 0x0001, 0)?;
    let adv = read_phy_ocp(io, PHY_ADV_2500)?;
    write_mii(io, MII_ANAR, ANAR_ABILITIES)?;
    write_mii(io, MII_100T2CR, GTCR_1000)?;
    write_phy_ocp(io, PHY_ADV_2500, adv | ADV_2500)?;
    write_mii(io, MII_BMCR, BMCR_RESET | BMCR_AUTOEN | BMCR_STARTNEG)?;
    Ok(Advertised {
        anar: read_mii(io, MII_ANAR)?,
        gtcr: read_mii(io, MII_100T2CR)?,
        adv_2500: read_phy_ocp(io, PHY_ADV_2500)?,
    })
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Speed {
    Down,
    Mbps10,
    Mbps100,
    Mbps1000,
    Mbps2500,
    /// Link bit set with no speed this backend knows.
    Unknown,
}

/// PHYSTAT decoded as `rge_ifmedia_sts` does; `true` with full duplex.
pub fn link(phystat: u16) -> (Speed, bool) {
    if phystat & PHYSTAT_LINK == 0 {
        return (Speed::Down, false);
    }
    // rge tests the bits in order and takes the first. A word with more
    // than one speed bit has no consistent meaning: reference_host's 8125B shows
    // 0x0493 (1000 and 2500) for seconds while negotiating from link-down
    // (#109 lane 2, wire-1 and p1-cold-wire). Treat it as Unknown.
    let speeds = PHYSTAT_10 | PHYSTAT_100 | PHYSTAT_1000 | PHYSTAT_2500;
    let speed = match phystat & speeds {
        PHYSTAT_10 => Speed::Mbps10,
        PHYSTAT_100 => Speed::Mbps100,
        PHYSTAT_1000 => Speed::Mbps1000,
        PHYSTAT_2500 => Speed::Mbps2500,
        _ => Speed::Unknown,
    };
    let full = phystat & PHYSTAT_FDX != 0 || matches!(speed, Speed::Mbps1000 | Speed::Mbps2500);
    (speed, full)
}

/// BMSR link status and autonegotiation complete.
const BMSR_LINK: u16 = 0x0004;
const BMSR_ANEG_COMPLETE: u16 = 0x0020;

/// Link as the PHY's BMSR reports it: link status (read twice, since it
/// latches link-down) and autonegotiation complete. BMSR is the register
/// shown to follow the cable: in #109 lane 2's diagnostic (run diag-1) it
/// went from 0x7989 to 0x79ad within about 0.1 s of the peer's link-up.
/// PHYSTAT did not. After S3 it read 0x0493 (LINK set, cable down), then
/// 0x04f3 (1000 and 2500 both set). PHYSTAT is kept only as a claim about
/// the speed (`phystat_claim`): one bit, or `Unknown`. A single stale bit
/// is indistinguishable from a fresh one, so callers report the speed as
/// unestablished; the link partner's own report is the speed evidence.
/// BMSR or PHYSTAT reading all ones is a vanished device (`DeviceGone`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CableLink {
    pub up: bool,
    pub phystat_claim: Speed,
    pub phystat: u16,
    pub bmsr: u16,
}

pub fn cable_link(io: &mut impl Io) -> Result<CableLink, Error> {
    let _ = read_mii(io, MII_BMSR)?;
    let bmsr = read_mii(io, MII_BMSR)?;
    let phystat = io.read16(PHYSTAT);
    if bmsr == u16::MAX || phystat == u16::MAX {
        return Err(Error::DeviceGone);
    }
    let up = bmsr & (BMSR_LINK | BMSR_ANEG_COMPLETE) == BMSR_LINK | BMSR_ANEG_COMPLETE;
    let phystat_claim = if up {
        match link(phystat).0 {
            Speed::Down => Speed::Unknown,
            speed => speed,
        }
    } else {
        Speed::Down
    };
    Ok(CableLink {
        up,
        phystat_claim,
        phystat,
        bmsr,
    })
}

// ---- S3: MAC loopback over one TX and one RX ring ----

const TXDESC_LO: u32 = 0x20;
const TXDESC_HI: u32 = 0x24;
const RXDESC_LO: u32 = 0xe4;
const RXDESC_HI: u32 = 0xe8;
const TXSTART: u32 = 0x90;
const CFG1: u32 = 0x52;
const TDFNR: u32 = 0x57;
const MAR0: u32 = 0x08;
const MAR4: u32 = 0x0c;
const INT_CFG0: u32 = 0x34;
const DLLPR: u32 = 0xd0;
const RXMAXSIZE: u32 = 0xda;
const EEE_TXIDLE_TIMER: u32 = 0x6048;
const RSS_CTRL: u32 = 0x4500;
const RXQUEUE_CTRL: u32 = 0x4800;
const INTMITI0: u32 = 0x0a00;

/// rge RGE_TXCFG_CONFIG and RGE_RXCFG_CONFIG_8125B (descriptor format v1).
const TXCFG_CONFIG: u32 = 0x0300_0700;
const RXCFG_CONFIG_8125B: u32 = 0x4100_0c00;
/// TXCFG LBK1:LBK0 = 01, MAC loopback, from the RTL8169 family's transmit
/// configuration register (not from rge; docs/RTL8125.md).
pub const TXCFG_LOOPBACK: u32 = 0x0002_0000;
const RXCFG_INDIV: u32 = 0x02;
const RXCFG_MULTI: u32 = 0x04;
const RXCFG_BROAD: u32 = 0x08;

/// Descriptor format v1: 32 bytes for TX and for RX.
pub const DESCRIPTOR_BYTES: usize = 32;
pub const OWN: u32 = 0x8000_0000;
pub const EOR: u32 = 0x4000_0000;
const TD_SOF: u32 = 0x2000_0000;
const TD_EOF: u32 = 0x1000_0000;
const TD_TXERR: u32 = 0x0080_0000;
/// rge `RGE_TDCMDSTS_EXCESSCOLL`: the frame was given up, not sent.
const TD_EXCESSCOLL: u32 = 0x0010_0000;
/// rge `RGE_TDCMDSTS_COLL`: collisions before a successful send (a count).
const TD_COLL: u32 = 0x000f_0000;
const RD_SOF: u32 = 0x0200_0000;
const RD_EOF: u32 = 0x0100_0000;
const RD_RXERRSUM: u32 = 0x0010_0000;
const RD_FRAGLEN: u32 = 0x3fff;
/// Byte offsets of the fields inside one descriptor.
pub const TX_CMDSTS: usize = 0;
pub const TX_ADDRESS: usize = 8;
pub const RX_ADDRESS: usize = 16;
/// `rge_extsts`, zeroed on every refill as rge_newbuf does.
pub const RX_EXTSTS: usize = 24;
pub const RX_CMDSTS: usize = 28;

/// The words of one TX descriptor handing a single-buffer frame of `len`
/// bytes to the chip. `last` marks the ring's final slot.
pub fn tx_cmdsts(len: usize, last: bool) -> u32 {
    debug_assert!(len <= 0xffff);
    OWN | TD_SOF | TD_EOF | len as u32 | if last { EOR } else { 0 }
}

/// An RX descriptor offering a buffer of `len` bytes to the chip.
pub fn rx_cmdsts(len: usize, last: bool) -> u32 {
    debug_assert!(len <= RD_FRAGLEN as usize);
    OWN | len as u32 | if last { EOR } else { 0 }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TxSlot {
    /// Still the chip's.
    Owned,
    /// Sent; collision information (`tx_collisions`) does not change that
    /// (rge counts it as collisions, not errors; re-review 3).
    Sent,
    /// Returned with TXERR or excessive collisions: not sent. Bits kept.
    Failed(u32),
}

pub fn tx_slot(cmdsts: u32) -> TxSlot {
    if cmdsts & OWN != 0 {
        TxSlot::Owned
    } else if cmdsts & (TD_TXERR | TD_EXCESSCOLL) != 0 {
        TxSlot::Failed(cmdsts)
    } else {
        TxSlot::Sent
    }
}

/// The collision count a completed TX descriptor reports (0..=15).
pub fn tx_collisions(cmdsts: u32) -> u32 {
    (cmdsts & TD_COLL) >> 16
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RxSlot {
    Owned,
    /// A whole frame in one buffer; the length includes the FCS if the chip
    /// kept it.
    Frame(usize),
    /// The chip flagged an error.
    Error(u32),
    /// Not both SOF and EOF, or a length beyond the offered buffer.
    Fragment(u32),
}

/// Classifies a returned RX descriptor. A frame must fit one buffer of
/// `offered` bytes; anything else is refused, never reassembled.
pub fn rx_slot(cmdsts: u32, offered: usize) -> RxSlot {
    if cmdsts & OWN != 0 {
        return RxSlot::Owned;
    }
    if cmdsts & RD_RXERRSUM != 0 {
        return RxSlot::Error(cmdsts);
    }
    let len = (cmdsts & RD_FRAGLEN) as usize;
    if cmdsts & (RD_SOF | RD_EOF) != RD_SOF | RD_EOF || len == 0 || len > offered {
        return RxSlot::Fragment(cmdsts);
    }
    RxSlot::Frame(len)
}

/// The loopback test frames: lengths cover the minimum, odd sizes and a
/// full-size frame; every byte is a function of (frame, offset).
pub const LOOPBACK_LENGTHS: [usize; 8] = [60, 64, 77, 128, 256, 511, 1000, 1514];
pub const LOOPBACK_ETHERTYPE: u16 = 0x88b5;

pub fn loopback_byte(mac: [u8; 6], frame: usize, offset: usize) -> u8 {
    match offset {
        0..=5 => mac[offset],
        6..=11 => mac[offset - 6],
        12 => (LOOPBACK_ETHERTYPE >> 8) as u8,
        13 => LOOPBACK_ETHERTYPE as u8,
        14 => frame as u8,
        _ => ((offset * 7 + frame * 31) as u8) ^ 0xa5,
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Mismatch {
    /// Received length is neither the sent length nor sent + 4 (FCS).
    Length { sent: usize, received: usize },
    Byte {
        offset: usize,
        sent: u8,
        received: u8,
    },
}

/// Compares a received frame with test frame `frame`. Returns whether the
/// chip kept the 4-byte FCS on the end.
pub fn check_loopback(mac: [u8; 6], frame: usize, received: &[u8]) -> Result<bool, Mismatch> {
    let sent = LOOPBACK_LENGTHS[frame];
    let fcs = match received.len() {
        n if n == sent => false,
        n if n == sent + 4 => true,
        n => {
            return Err(Mismatch::Length { sent, received: n });
        }
    };
    for (offset, &byte) in received[..sent].iter().enumerate() {
        let expected = loopback_byte(mac, frame, offset);
        if byte != expected {
            return Err(Mismatch::Byte {
                offset,
                sent: expected,
                received: byte,
            });
        }
    }
    Ok(fcs)
}

/// The rge_init MAC configuration for one queue on the 8125B, without the
/// PCI/CSI config writes, interrupt sources, offloads and the advertisement
/// (docs/RTL8125.md). Ring bases are installed; TX/RX stay disabled and no
/// doorbell is rung. `loopback` sets TXCFG's MAC loopback field.
pub fn configure_mac(
    io: &mut impl Io,
    mac: [u8; 6],
    tx_ring: u64,
    rx_ring: u64,
    loopback: bool,
) -> Result<(), Error> {
    if tx_ring & 0xff != 0 || rx_ring & 0xff != 0 {
        return Err(Error::InvalidRing);
    }
    // rge_set_macaddr.
    update8(io, EECMD, 0, EECMD_WRITECFG);
    io.write32(IDR0, u32::from_le_bytes([mac[0], mac[1], mac[2], mac[3]]));
    io.write32(IDR4, u32::from(mac[5]) << 8 | u32::from(mac[4]));
    update8(io, EECMD, EECMD_WRITECFG, 0);

    update8(io, EECMD, 0, EECMD_WRITECFG);
    update8(io, REG_F1, 0x80, 0);
    disable_aspm_clkreq(io);
    io.write16(EEE_TXIDLE_TIMER, 16362 + 14 + 32);
    io.write32(RXDESC_LO, rx_ring as u32);
    io.write32(RXDESC_HI, (rx_ring >> 32) as u32);
    io.write32(TXDESC_LO, tx_ring as u32);
    io.write32(TXDESC_HI, (tx_ring >> 32) as u32);
    io.write32(RXCFG, RXCFG_CONFIG_8125B);
    io.write32(
        TXCFG,
        TXCFG_CONFIG | if loopback { TXCFG_LOOPBACK } else { 0 },
    );
    io.write16(0x0382, 0x221b);
    io.write32(RSS_CTRL, 0);
    let queues = io.read16(RXQUEUE_CTRL) & !0x001c;
    io.write16(RXQUEUE_CTRL, queues);
    update8(io, CFG1, 0x10, 0);
    write_mac_ocp(io, 0xc140, 0xffff);
    write_mac_ocp(io, 0xc142, 0xffff);
    mac_update(io, 0xeb58, 0, 0x0001);
    mac_update(io, 0xe614, 0x0700, 0x0200);
    mac_update(io, 0xe63e, 0x0c00, 0);
    mac_update(io, 0xe63e, 0x0030, 0x0020);
    mac_update(io, 0xc0b4, 0x0001, 0);
    mac_update(io, 0xc0b4, 0, 0x0001);
    mac_update(io, 0xc0b4, 0, 0x000c);
    mac_update(io, 0xeb6a, 0x00ff, 0x0033);
    mac_update(io, 0xeb50, 0x03e0, 0x0040);
    mac_update(io, 0xe056, 0x00f0, 0);
    io.write8(TDFNR, 0x10);
    mac_update(io, 0xe040, 0x1000, 0);
    mac_update(io, 0xea1c, 0x0003, 0x0001);
    write_mac_ocp(io, 0xe0c0, 0x4000);
    mac_update(io, 0xe052, 0, 0x0060);
    mac_update(io, 0xe052, 0x0088, 0);
    mac_update(io, 0xd430, 0x0fff, 0x045f);
    update8(io, DLLPR, 0, 0xc0);
    update8(io, PPSW, 0, 0x40);
    mac_update(io, 0xe080, 0x0002, 0);
    mac_update(io, 0xea1c, 0x0004, 0);
    mac_update(io, 0xeb54, 0, 0x0001);
    delay(io, 1)?;
    mac_update(io, 0xeb54, 0x0001, 0);
    let value = io.read16(0x1880);
    io.write16(0x1880, value & !0x0030);
    update8(io, INT_CFG0, 0x01, 0);
    for timer in [TIMERINT0, TIMERINT1, TIMERINT2, TIMERINT3] {
        io.write32(timer, 0);
    }
    for i in 0..32 {
        io.write32(INTMITI0 + i * 4, 0);
    }
    mac_update(io, 0xc0ac, 0, 0x1f80);
    write_mac_ocp(io, 0xe098, 0xc302);
    mac_update(io, 0xe032, 0x0003, 0);
    mac_update(io, 0xe092, 0x00ff, 0);
    io.write16(RXMAXSIZE, 16384);
    update8(io, PPSW, 0x08, 0);
    // rge_iff without multicast: our address and broadcast only.
    let rxcfg = io.read32(RXCFG) & !RXCFG_ACCEPT;
    io.write32(RXCFG, rxcfg | RXCFG_INDIV | RXCFG_BROAD | RXCFG_MULTI);
    io.write32(MAR0, 0);
    io.write32(MAR4, 0);
    disable_aspm_clkreq(io);
    update8(io, EECMD, EECMD_WRITECFG, 0);
    delay(io, 1)?;
    Ok(())
}

/// TX and RX on, then the doorbell. The caller has already armed bus
/// mastering over fully built rings.
pub fn start(io: &mut impl Io) {
    io.write8(CMD, CMD_TXENB | CMD_RXENB);
    io.write16(TXSTART, 1);
}

/// TX and RX on without the doorbell: for the NIC, whose TX ring is empty
/// until the first send.
pub fn enable(io: &mut impl Io) {
    io.write8(CMD, CMD_TXENB | CMD_RXENB);
}

/// The TX doorbell alone, for a ring that is already running.
pub fn doorbell(io: &mut impl Io) {
    io.write16(TXSTART, 1);
}

/// The chip side of release: interrupts masked and acknowledged, RX
/// accept cleared, stop request, FIFOs drained, TX/RX disabled, soft reset
/// (`settle`: undrained FIFOs after a retry are an error), then, only once
/// the chip is shown stopped, the ring base registers cleared so it holds
/// no address of ABSD memory. After any error nothing more is written: how
/// a chip that did not stop treats a changed ring base is unestablished
/// (Codex 1), and its memory stays the device's (quarantined by the
/// caller). Bus mastering is the caller's, afterwards.
pub fn quiesce(io: &mut impl Io) -> Result<Waits, Error> {
    let waits = settle(io)?;
    let cmd = io.read8(CMD);
    if cmd == u8::MAX {
        return Err(Error::DeviceGone);
    }
    if cmd & (CMD_TXENB | CMD_RXENB) != 0 {
        return Err(Error::StillEnabled);
    }
    for reg in [TXDESC_LO, TXDESC_HI, RXDESC_LO, RXDESC_HI] {
        io.write32(reg, 0);
    }
    Ok(waits)
}

/// What the read-only probe saw.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Identity {
    pub chip: Chip,
    pub txcfg: u32,
    /// IDR0..5: the station address the MAC currently filters on.
    pub mac: [u8; 6],
    /// ADDR0/ADDR1: the address rge copies into IDR at attach.
    pub permanent: [u8; 6],
    pub phy_id: u32,
    pub bmcr: u16,
    pub bmsr: u16,
    pub anar: u16,
    pub phystat: u16,
    pub cmd: u8,
    pub imr: u32,
    pub rxcfg: u32,
}

/// Reads identity only. The only writes are OCP read commands (an address
/// into MACOCP/PHYOCP); no register that configures the chip is written.
/// The chip is judged before any OCP access.
pub fn identify(io: &mut impl Io) -> Result<Identity, Error> {
    let txcfg = io.read32(TXCFG);
    if txcfg == u32::MAX {
        return Err(Error::NotDecoding);
    }
    let chip = chip(txcfg)?;
    let mac = mac_from(io.read32(IDR0), io.read32(IDR4));
    let permanent = mac_from(io.read32(ADDR0), io.read32(ADDR1));
    if !valid_mac(permanent) {
        return Err(Error::InvalidMac);
    }
    let high = read_mii(io, MII_PHYIDR1)?;
    let low = read_mii(io, MII_PHYIDR2)?;
    Ok(Identity {
        chip,
        txcfg,
        mac,
        permanent,
        phy_id: u32::from(high) << 16 | u32::from(low),
        bmcr: read_mii(io, MII_BMCR)?,
        bmsr: read_mii(io, MII_BMSR)?,
        anar: read_mii(io, MII_ANAR)?,
        phystat: io.read16(PHYSTAT),
        cmd: io.read8(CMD),
        imr: io.read32(IMR),
        rxcfg: io.read32(RXCFG),
    })
}

#[cfg(test)]
pub(crate) mod fake {
    extern crate std;
    use super::*;
    use std::collections::BTreeMap;
    use std::vec::Vec;

    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub enum Op {
        Read(u32),
        Write(u32, u32, u8),
        Delay(u32),
    }

    /// A register file with the OCP windows behind MACOCP and PHYOCP.
    /// `phy_ready_after` delays the PHY OCP flag by that many reads.
    pub struct Fake {
        pub registers: BTreeMap<u32, u32>,
        pub mac_ocp: BTreeMap<u16, u16>,
        pub phy_ocp: BTreeMap<u16, u16>,
        pub trace: Vec<Op>,
        pub phy_ready_after: u32,
        /// The soft reset bit never clears.
        pub reset_sticky: bool,
        /// The function stopped decoding: every read returns all ones.
        pub gone: bool,
        pending: u32,
        phy_latch: u32,
    }

    impl Fake {
        /// reference_host's 02:00.0 as the earlier survey and r8169 report it, except
        /// its station address, replaced by a synthetic locally administered
        /// one (02:12:51:25:00:01; MACs are not published).
        pub fn reference_host() -> Self {
            let mut registers = BTreeMap::new();
            registers.insert(TXCFG, 0x6410_0700);
            registers.insert(IDR0, 0x2551_1202);
            registers.insert(IDR4, 0x0000_0100);
            registers.insert(ADDR0, 0x2551_1202);
            registers.insert(ADDR1, 0x0000_0100);
            registers.insert(PHYSTAT, 0x000b);
            // MCUCMD FIFOs empty (0xd3), IM idle 0x0103 (0xe2).
            registers.insert(0xd0, 0x3000_0000);
            registers.insert(0xe0, 0x0103_0000);
            let mut phy_ocp = BTreeMap::new();
            phy_ocp.insert(0xa420, 3);
            phy_ocp.insert(mii_ocp(MII_ANAR), 0x11e1);
            phy_ocp.insert(mii_ocp(MII_PHYIDR1), 0x001c);
            phy_ocp.insert(mii_ocp(MII_PHYIDR2), 0xc849);
            phy_ocp.insert(mii_ocp(MII_BMCR), 0x1040);
            Self {
                registers,
                mac_ocp: BTreeMap::new(),
                phy_ocp,
                trace: Vec::new(),
                phy_ready_after: 0,
                reset_sticky: false,
                gone: false,
                pending: 0,
                phy_latch: 0,
            }
        }
        pub fn writes(&self) -> impl Iterator<Item = (u32, u32)> + '_ {
            self.trace.iter().filter_map(|op| match op {
                Op::Write(offset, value, _) => Some((*offset, *value)),
                _ => None,
            })
        }
        fn get(&self, offset: u32) -> u32 {
            if self.gone {
                return u32::MAX;
            }
            let base = offset & !3;
            let word = self.registers.get(&base).copied().unwrap_or(0);
            word >> ((offset & 3) * 8)
        }
        fn put(&mut self, offset: u32, value: u32, width: u8) {
            self.trace.push(Op::Write(offset, value, width));
            match (offset, width) {
                (MACOCP, 4) => {
                    let reg = ((value >> 16) as u16 & 0x7fff) << 1;
                    if value & OCP_BUSY != 0 {
                        self.mac_ocp.insert(reg, value as u16);
                    } else {
                        let data = self.mac_ocp.get(&reg).copied().unwrap_or(0);
                        self.registers.insert(MACOCP, value | u32::from(data));
                    }
                    return;
                }
                (PHYOCP, 4) => {
                    let reg = ((value >> 16) as u16 & 0x7fff) << 1;
                    self.pending = self.phy_ready_after;
                    if value & OCP_BUSY != 0 {
                        let mut data = value as u16;
                        if reg == mii_ocp(MII_BMCR) {
                            data &= !BMCR_RESET;
                        }
                        self.phy_ocp.insert(reg, data);
                        self.phy_latch = value;
                    } else {
                        let data = self.phy_ocp.get(&reg).copied().unwrap_or(0);
                        self.phy_latch = value | u32::from(data);
                    }
                    return;
                }
                _ => {}
            }
            let value = if offset == CMD && width == 1 && !self.reset_sticky {
                value & !u32::from(CMD_RESET)
            } else if offset == EPHYAR {
                value & !EPHYAR_BUSY
            } else {
                value
            };
            let base = offset & !3;
            let shift = (offset & 3) * 8;
            let mask = match width {
                1 => 0xffu32,
                2 => 0xffff,
                _ => u32::MAX,
            } << shift;
            let old = self.registers.get(&base).copied().unwrap_or(0);
            self.registers
                .insert(base, (old & !mask) | ((value << shift) & mask));
        }
    }

    impl Io for Fake {
        fn read8(&mut self, offset: u32) -> u8 {
            self.trace.push(Op::Read(offset));
            self.get(offset) as u8
        }
        fn read16(&mut self, offset: u32) -> u16 {
            self.trace.push(Op::Read(offset));
            self.get(offset) as u16
        }
        fn read32(&mut self, offset: u32) -> u32 {
            self.trace.push(Op::Read(offset));
            if self.gone {
                return u32::MAX;
            }
            if offset == PHYOCP {
                // In flight the flag reads as written; once done it flips
                // (set for a read's data-valid, clear for a taken write).
                if self.pending > 0 {
                    self.pending -= 1;
                    return self.phy_latch;
                }
                return self.phy_latch ^ OCP_BUSY;
            }
            self.get(offset)
        }
        fn write8(&mut self, offset: u32, value: u8) {
            self.put(offset, u32::from(value), 1)
        }
        fn write16(&mut self, offset: u32, value: u16) {
            self.put(offset, u32::from(value), 2)
        }
        fn write32(&mut self, offset: u32, value: u32) {
            self.put(offset, value, 4)
        }
        fn delay_ms(&mut self, milliseconds: u32) -> bool {
            self.trace.push(Op::Delay(milliseconds));
            true
        }
    }
}

#[cfg(test)]
mod tests {
    extern crate std;
    use super::fake::Fake;
    use super::*;

    #[test]
    fn revision_decoding_admits_only_the_8125b() {
        assert_eq!(chip(0x6410_0000), Ok(Chip::Rtl8125b));
        // Bits outside HWREV (the configured DMA burst, IFG) do not matter.
        assert_eq!(chip(0x6410_0700 | 0x0300_0000), Ok(Chip::Rtl8125b));
        for (txcfg, hwrev) in [
            (0x6090_0700, 0x6090_0000), // RTL8125A
            (0x6880_0000, 0x6880_0000), // RTL8125D
            (0x6490_0000, 0x6490_0000), // RTL8126
            (0x6c90_0000, 0x6c90_0000), // RTL8127
            (0x0000_0000, 0x0000_0000),
            (0xffff_ffff, 0x7cf0_0000),
        ] {
            assert_eq!(chip(txcfg), Err(Error::UnsupportedRevision(hwrev)));
        }
        assert_eq!(xid(0x6410_0700), 0x641);
        assert_eq!(xid(0x6090_0000), 0x609);
    }

    #[test]
    fn mac_bytes_and_validity() {
        let mac = mac_from(0x2551_1202, 0xdead_0100);
        assert_eq!(mac, [0x02, 0x12, 0x51, 0x25, 0x00, 0x01]);
        assert!(valid_mac(mac));
        assert!(!valid_mac([0; 6]));
        assert!(!valid_mac([0xff; 6]));
        assert!(!valid_mac([0x01, 0, 0x5e, 0, 0, 1]));
    }

    #[test]
    fn mii_registers_map_onto_phy_ocp_as_rge_computes_them() {
        assert_eq!(mii_ocp(MII_BMCR), 0xa400);
        assert_eq!(mii_ocp(MII_BMSR), 0xa402);
        assert_eq!(mii_ocp(MII_PHYIDR1), 0xa404);
        assert_eq!(mii_ocp(MII_PHYIDR2), 0xa406);
        assert_eq!(mii_ocp(MII_ANAR), 0xa408);
        assert_eq!(mii_ocp(7), 0xa40e);
        assert_eq!(mii_ocp(8), 0xa410);
        assert_eq!(mii_ocp(MII_100T2CR), 0xa412);
    }

    #[test]
    fn ocp_commands_encode_the_halved_address() {
        let mut fake = Fake::reference_host();
        write_mac_ocp(&mut fake, 0xe614, 0x0200);
        write_phy_ocp(&mut fake, 0xa5d4, 0x0080).unwrap();
        let writes: std::vec::Vec<_> = fake.writes().collect();
        assert_eq!(
            writes,
            [
                (MACOCP, 0x8000_0000 | 0x730a << 16 | 0x0200),
                (PHYOCP, 0x8000_0000 | 0x52ea << 16 | 0x0080),
            ]
        );
        assert_eq!(read_mac_ocp(&mut fake, 0xe614), 0x0200);
        assert_eq!(read_phy_ocp(&mut fake, 0xa5d4), Ok(0x0080));
    }

    #[test]
    fn phy_ocp_waits_for_the_flag_and_is_bounded() {
        let mut fake = Fake::reference_host();
        fake.phy_ready_after = 5;
        assert_eq!(read_mii(&mut fake, MII_PHYIDR1), Ok(0x001c));
        fake.phy_ready_after = OCP_POLLS - 1;
        assert_eq!(read_mii(&mut fake, MII_PHYIDR2), Ok(0xc849));
        fake.phy_ready_after = OCP_POLLS;
        assert_eq!(read_mii(&mut fake, MII_PHYIDR2), Err(Error::PhyOcpTimeout));
        assert_eq!(
            write_phy_ocp(&mut fake, 0xa5d4, 1),
            Err(Error::PhyOcpTimeout)
        );
    }

    #[test]
    fn identify_reads_reference_host_and_writes_only_ocp_addresses() {
        let mut fake = Fake::reference_host();
        let id = identify(&mut fake).unwrap();
        assert_eq!(id.chip, Chip::Rtl8125b);
        assert_eq!(id.mac, [0x02, 0x12, 0x51, 0x25, 0x00, 0x01]);
        assert_eq!(id.permanent, id.mac);
        assert_eq!(id.phy_id, 0x001c_c849);
        assert_eq!(id.phystat & PHYSTAT_LINK, PHYSTAT_LINK);
        for (offset, value) in fake.writes() {
            assert!(offset == PHYOCP && value & OCP_BUSY == 0, "{offset:#x}");
        }
    }

    #[test]
    fn identify_refuses_before_any_ocp_access() {
        for txcfg in [u32::MAX, 0x6090_0000] {
            let mut fake = Fake::reference_host();
            fake.registers.insert(TXCFG, txcfg);
            assert!(identify(&mut fake).is_err());
            assert_eq!(fake.writes().count(), 0);
        }
        let mut fake = Fake::reference_host();
        fake.registers.insert(ADDR0, 0);
        fake.registers.insert(ADDR1, 0);
        assert_eq!(identify(&mut fake), Err(Error::InvalidMac));
        assert_eq!(fake.writes().count(), 0);
    }

    fn mac_ocp_writes(fake: &Fake) -> std::vec::Vec<(u16, u16)> {
        fake.writes()
            .filter(|(offset, value)| *offset == MACOCP && value & OCP_BUSY != 0)
            .map(|(_, value)| (((value >> 16) as u16 & 0x7fff) << 1, value as u16))
            .collect()
    }

    fn phy_ocp_writes(fake: &Fake) -> std::vec::Vec<(u16, u16)> {
        fake.writes()
            .filter(|(offset, value)| *offset == PHYOCP && value & OCP_BUSY != 0)
            .map(|(_, value)| (((value >> 16) as u16 & 0x7fff) << 1, value as u16))
            .collect()
    }

    fn no_dma_or_patch(fake: &Fake) {
        for (offset, value) in fake.writes() {
            // Ring base registers, TX doorbell, TX/RX enable.
            assert!(![0x20, 0x24, 0x90, 0xe4, 0xe8].contains(&offset));
            if offset == CMD {
                assert_eq!(value as u8 & (CMD_TXENB | CMD_RXENB), 0);
            }
        }
        // MAC MCU RAM (0xf800..0xf9fe) is the firmware's MAC patch table.
        assert!(
            mac_ocp_writes(fake)
                .iter()
                .all(|(reg, _)| !(0xf800..=0xf9fe).contains(reg))
        );
        // 0xb820 bit 4 requests a PHY MCU patch window.
        assert!(phy_ocp_writes(fake).iter().all(|(reg, _)| *reg != 0xb820));
    }

    #[test]
    fn chip_init_clears_mcu_break_points_and_loads_no_patch() {
        let mut fake = Fake::reference_host();
        let init = chip_init(&mut fake).unwrap();
        assert_eq!(init.phy_state, 3);
        assert!(init.hw_reset.fifos_empty && init.hw_reset.idle);
        no_dma_or_patch(&fake);
        let mac = mac_ocp_writes(&fake);
        for reg in (0xfc26..=0xfc48).step_by(2) {
            assert!(mac.contains(&(reg, 0)), "{reg:#x}");
        }
        // Chip interrupts masked before the final reset.
        assert!(fake.writes().any(|w| w == (IMR, 0)));
        assert_eq!(
            fake.writes()
                .filter(|w| *w == (CMD, u32::from(CMD_RESET)))
                .count(),
            2
        );
    }

    #[test]
    fn a_reset_that_never_completes_is_fatal_and_not_retried() {
        let mut fake = Fake::reference_host();
        fake.reset_sticky = true;
        assert_eq!(chip_init(&mut fake), Err(Error::ResetTimeout));
        assert_eq!(
            fake.writes()
                .filter(|w| *w == (CMD, u32::from(CMD_RESET)))
                .count(),
            1
        );
        // Nothing after the failed reset reaches the MAC MCU or the PHY.
        let after = fake
            .trace
            .iter()
            .rposition(|op| *op == super::fake::Op::Write(CMD, u32::from(CMD_RESET), 1))
            .unwrap();
        assert!(
            fake.trace[after + 1..]
                .iter()
                .all(|op| !matches!(op, super::fake::Op::Write(..)))
        );
    }

    #[test]
    fn undrained_fifos_are_reported_not_fatal() {
        let mut fake = Fake::reference_host();
        fake.registers.insert(0xd0, 0);
        fake.registers.insert(0xe0, 0);
        let waits = reset(&mut fake).unwrap();
        assert_eq!(
            waits,
            Waits {
                fifos_empty: false,
                idle: false,
                mcucmd: 0
            }
        );
    }

    #[test]
    fn phy_config_reads_the_ram_code_and_applies_no_patch() {
        let mut fake = Fake::reference_host();
        fake.phy_ocp.insert(0xa438, 0x0000);
        let rcode = phy_config(&mut fake, true).unwrap();
        assert_eq!(rcode, 0);
        no_dma_or_patch(&fake);
        // Every speed is withdrawn before the PHY reset.
        let phy = phy_ocp_writes(&fake);
        let reset = phy
            .iter()
            .position(|w| *w == (mii_ocp(MII_BMCR), 0x9200))
            .unwrap();
        assert!(phy[..reset].contains(&(mii_ocp(MII_ANAR), 0x1001)));
        assert!(phy[..reset].contains(&(mii_ocp(MII_100T2CR), 0)));
    }

    #[test]
    fn advertisement_is_written_whole_from_either_reset_state() {
        // Cold: 10/100 only. Warm: everything including 2.5G already set.
        let mut writes = std::vec::Vec::new();
        for (anar, gtcr, adv) in [(0x11e1, 0x0000, 0x0000), (0x1de1, 0x0300, 0x0080)] {
            let mut fake = Fake::reference_host();
            fake.phy_ocp.insert(mii_ocp(MII_ANAR), anar);
            fake.phy_ocp.insert(mii_ocp(MII_100T2CR), gtcr);
            fake.phy_ocp.insert(PHY_ADV_2500, adv);
            let got = advertise_all(&mut fake).unwrap();
            assert_eq!(
                got,
                Advertised {
                    anar: 0x01e0,
                    gtcr: 0x0300,
                    adv_2500: ADV_2500
                }
            );
            no_dma_or_patch(&fake);
            let phy = phy_ocp_writes(&fake);
            assert_eq!(phy.last(), Some(&(mii_ocp(MII_BMCR), 0x9200)));
            writes.push(phy);
        }
        assert_eq!(writes[0], writes[1]);
    }

    #[test]
    fn link_decoding() {
        assert_eq!(link(0x0000), (Speed::Down, false));
        assert_eq!(link(0x0409), (Speed::Down, false));
        assert_eq!(link(0x008b), (Speed::Mbps100, true));
        assert_eq!(link(0x000a), (Speed::Mbps100, false));
        assert_eq!(link(0x0402), (Speed::Mbps2500, true));
        assert_eq!(link(0x0012), (Speed::Mbps1000, true));
        assert_eq!(link(0x0007), (Speed::Mbps10, true));
        assert_eq!(link(0x1002), (Speed::Unknown, false));
        // Observed on reference_host while negotiating from link-down; rge's order
        // would call it 1000.
        assert_eq!(link(0x0493).0, Speed::Unknown);
        assert_eq!(link(0x04e3), (Speed::Mbps2500, true));
    }

    #[test]
    fn cable_link_follows_bmsr_from_the_post_s3_start() {
        let bmsr = mii_ocp(MII_BMSR);
        // diag-1: after S3 nothing is advertised; PHYSTAT claims link while
        // the cable is down, then shows two speeds once it is up.
        for (phystat, status, up, speed) in [
            (0x0493, 0x7989, false, Speed::Down),
            (0x04f3, 0x79ad, true, Speed::Unknown),
            (0x04e3, 0x79ad, true, Speed::Mbps2500),
            (0x0000, 0x79ad, true, Speed::Unknown),
            (0x04e3, 0x7989, false, Speed::Down), // negotiation not complete
            (0x04e3, 0x79a9, false, Speed::Down), // PHY link status low
        ] {
            let mut fake = Fake::reference_host();
            fake.registers.insert(PHYSTAT, phystat);
            fake.phy_ocp.insert(bmsr, status);
            let got = cable_link(&mut fake).unwrap();
            assert_eq!(
                (got.up, got.phystat_claim),
                (up, speed),
                "{phystat:#x} {status:#x}"
            );
        }
    }

    const MAC: [u8; 6] = [0x02, 0x12, 0x51, 0x25, 0x00, 0x01];

    #[test]
    fn descriptor_words() {
        assert_eq!(tx_cmdsts(60, false), 0xb000_003c);
        assert_eq!(tx_cmdsts(1514, true), 0xf000_05ea);
        assert_eq!(rx_cmdsts(2048, false), 0x8000_0800);
        assert_eq!(rx_cmdsts(2048, true), 0xc000_0800);
        assert_eq!(tx_slot(0xb000_003c), TxSlot::Owned);
        assert_eq!(tx_slot(0x3000_003c), TxSlot::Sent);
        assert_eq!(tx_slot(0x3080_003c), TxSlot::Failed(0x3080_003c));
        // Re-review 3, expected from if_rgereg.h's TDCMDSTS bits: a
        // collision count alone is a sent frame; EXCESSCOLL and TXERR are not.
        assert_eq!(tx_slot(0x0001_003c), TxSlot::Sent);
        assert_eq!(tx_collisions(0x0001_003c), 1);
        assert_eq!(tx_slot(0x300f_003c), TxSlot::Sent);
        assert_eq!(tx_collisions(0x300f_003c), 15);
        assert_eq!(tx_slot(0x3010_003c), TxSlot::Failed(0x3010_003c));
        assert_eq!(tx_slot(0x3081_003c), TxSlot::Failed(0x3081_003c));
        assert_eq!(tx_collisions(0x3000_003c), 0);
    }

    #[test]
    fn rx_slots_accept_only_whole_frames_inside_the_offered_buffer() {
        assert_eq!(rx_slot(0x8000_0800, 2048), RxSlot::Owned);
        assert_eq!(rx_slot(0x0300_0040, 2048), RxSlot::Frame(64));
        assert_eq!(rx_slot(0x4300_05ee, 2048), RxSlot::Frame(1518));
        assert_eq!(rx_slot(0x0310_0040, 2048), RxSlot::Error(0x0310_0040));
        for cmdsts in [0x0200_0040, 0x0100_0040, 0x0000_0040, 0x0300_0000] {
            assert_eq!(rx_slot(cmdsts, 2048), RxSlot::Fragment(cmdsts));
        }
        assert_eq!(rx_slot(0x0300_0041, 64), RxSlot::Fragment(0x0300_0041));
    }

    fn frame(index: usize, fcs: bool) -> std::vec::Vec<u8> {
        let mut bytes: std::vec::Vec<u8> = (0..LOOPBACK_LENGTHS[index])
            .map(|offset| loopback_byte(MAC, index, offset))
            .collect();
        if fcs {
            bytes.extend_from_slice(&[1, 2, 3, 4]);
        }
        bytes
    }

    #[test]
    fn loopback_comparison_is_exact() {
        for index in 0..LOOPBACK_LENGTHS.len() {
            assert_eq!(check_loopback(MAC, index, &frame(index, false)), Ok(false));
            assert_eq!(check_loopback(MAC, index, &frame(index, true)), Ok(true));
        }
        let f = frame(3, false);
        assert_eq!(&f[..6], &MAC);
        assert_eq!(&f[12..14], &[0x88, 0xb5]);
        // The frames differ from each other, so a swapped buffer is caught.
        assert!(check_loopback(MAC, 0, &frame(1, false)[..60]).is_err());
        let mut f = frame(7, true);
        f[1000] ^= 1;
        assert_eq!(
            check_loopback(MAC, 7, &f),
            Err(Mismatch::Byte {
                offset: 1000,
                sent: f[1000] ^ 1,
                received: f[1000]
            })
        );
        for len in [59, 61, 62, 63, 65] {
            assert_eq!(
                check_loopback(MAC, 0, &frame(7, false)[..len]),
                Err(Mismatch::Length {
                    sent: 60,
                    received: len
                })
            );
        }
    }

    #[test]
    fn mac_configuration_installs_rings_but_never_starts_the_chip() {
        for loopback in [true, false] {
            let mut fake = Fake::reference_host();
            configure_mac(&mut fake, MAC, 0x0012_3400, 0x0001_0000_5600, loopback).unwrap();
            let writes: std::vec::Vec<_> = fake.writes().collect();
            for w in [(0x20, 0x0012_3400), (0x24, 0), (0xe4, 0x5600), (0xe8, 1)] {
                assert!(writes.contains(&w), "{w:x?}");
            }
            let txcfg = TXCFG_CONFIG | if loopback { TXCFG_LOOPBACK } else { 0 };
            assert!(writes.contains(&(TXCFG, txcfg)));
            for (offset, value) in &writes {
                assert_ne!(*offset, 0x90, "doorbell");
                if *offset == CMD {
                    assert_eq!(*value as u8 & (CMD_TXENB | CMD_RXENB), 0);
                }
                assert_ne!(*offset, IMR, "no interrupt source enabled");
            }
            assert_eq!(fake.registers[&RXCFG] & RXCFG_ACCEPT, 0x0e);
        }
        let mut fake = Fake::reference_host();
        assert_eq!(
            configure_mac(&mut fake, MAC, 0x0012_3480, 0x5600, true),
            Err(Error::InvalidRing)
        );
        assert_eq!(fake.writes().count(), 0);
    }

    #[test]
    fn quiesce_stops_the_chip_and_forgets_the_rings() {
        let mut fake = Fake::reference_host();
        configure_mac(&mut fake, MAC, 0x1000, 0x2000, true).unwrap();
        start(&mut fake);
        assert_eq!(
            fake.registers[&0x34] >> 24,
            u32::from(CMD_TXENB | CMD_RXENB)
        );
        fake.trace.clear();
        quiesce(&mut fake).unwrap();
        let writes: std::vec::Vec<_> = fake.writes().collect();
        let imr = writes.iter().position(|w| *w == (IMR, 0)).unwrap();
        let reset = writes
            .iter()
            .position(|w| *w == (CMD, u32::from(CMD_RESET)))
            .unwrap();
        assert!(imr < reset);
        for reg in [0x20, 0x24, 0xe4, 0xe8] {
            let at = writes.iter().position(|w| *w == (reg, 0)).unwrap();
            assert!(at > reset);
        }
        assert_eq!(fake.registers[&0x34] >> 24 & 0x0c, 0);
        // A reset that never completes masks and stops, but leaves the ring
        // bases alone: the chip is not shown stopped (Codex 1).
        let mut fake = Fake::reference_host();
        fake.reset_sticky = true;
        assert_eq!(quiesce(&mut fake), Err(Error::ResetTimeout));
        assert!(fake.writes().any(|w| w == (IMR, 0)));
        for reg in [0x20, 0x24, 0xe4, 0xe8] {
            assert!(fake.writes().all(|(offset, _)| offset != reg), "{reg:#x}");
        }
    }

    /// F4: FIFOs that never report empty after a reset and one retry are
    /// not quiescent, for release and for bring-up alike.
    #[test]
    fn undrained_fifos_after_a_retry_are_not_quiescent() {
        let mut fake = Fake::reference_host();
        fake.registers.insert(0xd0, 0);
        assert_eq!(quiesce(&mut fake), Err(Error::StopUnconfirmed));
        assert_eq!(
            fake.writes()
                .filter(|w| *w == (CMD, u32::from(CMD_RESET)))
                .count(),
            2,
            "one retry"
        );
        for reg in [0x20, 0x24, 0xe4, 0xe8] {
            assert!(fake.writes().all(|(offset, _)| offset != reg), "{reg:#x}");
        }
        let mut fake = Fake::reference_host();
        fake.registers.insert(0xd0, 0);
        assert_eq!(chip_init(&mut fake), Err(Error::StopUnconfirmed));
        // Drained FIFOs: one reset is enough.
        let mut fake = Fake::reference_host();
        assert!(settle(&mut fake).unwrap().fifos_empty);
        assert_eq!(
            fake.writes()
                .filter(|w| *w == (CMD, u32::from(CMD_RESET)))
                .count(),
            1
        );
    }

    /// Re-review 1: FIFOs empty but the idle indication absent is not a
    /// confirmed stop either; release and bring-up refuse alike.
    #[test]
    fn empty_fifos_without_idle_are_not_a_confirmed_stop() {
        let mut fake = Fake::reference_host();
        fake.registers.insert(0xe0, 0);
        let first = hw_reset(&mut fake).unwrap();
        assert!(first.fifos_empty && !first.idle);
        let mut fake = Fake::reference_host();
        fake.registers.insert(0xe0, 0);
        assert_eq!(quiesce(&mut fake), Err(Error::StopUnconfirmed));
        for reg in [0x20, 0x24, 0xe4, 0xe8] {
            assert!(fake.writes().all(|(offset, _)| offset != reg), "{reg:#x}");
        }
        let mut fake = Fake::reference_host();
        fake.registers.insert(0xe0, 0);
        assert_eq!(chip_init(&mut fake), Err(Error::StopUnconfirmed));
    }

    /// F3: the advertisement never offers pause, from any starting ANAR.
    #[test]
    fn pause_is_never_advertised() {
        for anar in [0x0000, 0x0de1, 0xffff] {
            let mut fake = Fake::reference_host();
            fake.phy_ocp.insert(mii_ocp(MII_ANAR), anar);
            let got = advertise_all(&mut fake).unwrap();
            assert_eq!(got.anar & ANAR_PAUSE, 0, "{anar:#x}");
            for (reg, value) in phy_ocp_writes(&fake) {
                if reg == mii_ocp(MII_ANAR) {
                    assert_eq!(value & ANAR_PAUSE, 0);
                }
            }
        }
    }

    /// F6 (Codex 3): all ones from a vanished function is an error at every
    /// layer that decides link, never BMSR 0xffff = link up.
    #[test]
    fn all_ones_reads_are_a_vanished_device_never_link() {
        let mut fake = Fake::reference_host();
        fake.gone = true;
        assert_eq!(read_phy_ocp(&mut fake, 0xa402), Err(Error::DeviceGone));
        assert_eq!(write_phy_ocp(&mut fake, 0xa402, 1), Err(Error::DeviceGone));
        assert_eq!(cable_link(&mut fake), Err(Error::DeviceGone));
        // A vanished chip never reads as stopped (its reset bit reads set).
        assert!(quiesce(&mut fake).is_err());
        // BMSR or PHYSTAT alone reading all ones is refused too.
        let mut fake = Fake::reference_host();
        fake.phy_ocp.insert(mii_ocp(MII_BMSR), 0xffff);
        assert_eq!(cable_link(&mut fake), Err(Error::DeviceGone));
        let mut fake = Fake::reference_host();
        fake.phy_ocp.insert(mii_ocp(MII_BMSR), 0x79ad);
        fake.registers.insert(PHYSTAT, 0xffff);
        assert_eq!(cable_link(&mut fake), Err(Error::DeviceGone));
    }

    #[test]
    fn the_untuned_variant_drops_only_the_8125b_constants() {
        let mut tuned = Fake::reference_host();
        let mut untuned = Fake::reference_host();
        assert_eq!(
            phy_config(&mut tuned, true),
            phy_config(&mut untuned, false)
        );
        let with = phy_ocp_writes(&tuned);
        let without = phy_ocp_writes(&untuned);
        // Every register the variant writes appears, in order, in the
        // control. Values may differ: EEE's read-modify-write of 0xa442
        // sees the bit the tuning set.
        let mut rest = with.iter();
        for (reg, _) in &without {
            assert!(rest.any(|(r, _)| r == reg), "{reg:#x}");
        }
        let tuning_regs = [
            0xa442, 0xac46, 0xad30, 0xb87c, 0xb87e, 0xbf00, 0xbf46, 0xa436, 0xa438, 0xa4ca, 0xbf84,
            0xa424,
        ];
        let dropped: std::vec::Vec<_> = with.iter().filter(|w| !without.contains(w)).collect();
        assert!(!dropped.is_empty());
        assert!(
            dropped.iter().all(|(reg, _)| tuning_regs.contains(reg)),
            "{dropped:x?}"
        );
        for reg in [
            0xb87c, 0xbf00, 0xbf46, 0xbf84, 0xac46, 0xad30, 0xa4ca, 0xa424,
        ] {
            assert!(without.iter().all(|(r, _)| *r != reg), "{reg:#x}");
        }
        assert_eq!(mac_ocp_writes(&tuned), mac_ocp_writes(&untuned));
    }
}
