//! Exact RTL8125 (10ec:8125) admission, before MMIO or PCI configuration writes.
//! The chip revision is judged later from TXCFG (`rtl8125::chip`); this only
//! decides whether the function's configuration space is one we may map.

use crate::dma_policy::VmEnvelopeObserved;
pub const VENDOR: u16 = 0x10ec;
pub const DEVICE: u16 = 0x8125;
/// The register window behind BAR2. Not sized: see `admit`.
pub const REGISTER_BYTES: u64 = 64 * 1024;
const BAR2: u8 = 0x18;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Refusal {
    Identity,
    Class,
    Header,
    Bar,
    Capabilities,
    PowerState,
    InterruptMode,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Admitted {
    /// Physical base of the 64 KiB register window.
    pub bar: u64,
    /// The command register as firmware left it (memory decode, bus master).
    pub command: u16,
    pub revision: u8,
}

/// Capability links are untrusted register data: aligned, bounded, no loops.
/// BAR sizing is deliberately absent: writing all ones can affect a live
/// device. Memory decode and bus mastering are reported, not judged: the
/// caller turns bus mastering off and decode on as its custody rules say.
pub fn admit(mut read: impl FnMut(u8) -> u32) -> Result<Admitted, Refusal> {
    if read(0) != (u32::from(DEVICE) << 16 | u32::from(VENDOR)) {
        return Err(Refusal::Identity);
    }
    let class = read(8);
    if class >> 8 != 0x020000 {
        return Err(Refusal::Class);
    }
    if (read(0x0c) >> 16) & 0x7f != 0 {
        return Err(Refusal::Header);
    }
    let command_status = read(4);
    // BAR2 must be a 64-bit memory BAR on a 64 KiB boundary.
    let low = read(BAR2);
    if low & 1 != 0 || (low >> 1) & 3 != 2 {
        return Err(Refusal::Bar);
    }
    let bar = u64::from(low & !0xf) | u64::from(read(BAR2 + 4)) << 32;
    if bar == 0 || bar & (REGISTER_BYTES - 1) != 0 {
        return Err(Refusal::Bar);
    }
    if command_status & (1 << 20) == 0 {
        return Err(Refusal::Capabilities);
    }
    let mut offset = (read(0x34) & 0xff) as u8;
    let mut seen = 0u64;
    let mut pm = false;
    while offset != 0 {
        if offset < 0x40 || offset & 3 != 0 {
            return Err(Refusal::Capabilities);
        }
        let bit = 1u64 << (offset / 4);
        if seen & bit != 0 {
            return Err(Refusal::Capabilities);
        }
        seen |= bit;
        let header = read(offset);
        match header as u8 {
            1 => {
                if pm || offset > 0xf8 {
                    return Err(Refusal::Capabilities);
                }
                pm = true;
                if read(offset + 4) & 3 != 0 {
                    return Err(Refusal::PowerState);
                }
            }
            5 if header & (1 << 16) != 0 => return Err(Refusal::InterruptMode),
            0x11 if header & (1 << 31) != 0 => return Err(Refusal::InterruptMode),
            0xff => return Err(Refusal::Capabilities),
            _ => {}
        }
        offset = (header >> 8) as u8;
    }
    if !pm {
        return Err(Refusal::Capabilities);
    }
    Ok(Admitted {
        bar,
        command: command_status as u16,
        revision: class as u8,
    })
}

/// What the boot can cheaply observe about where it runs, read before bus
/// mastering is ever set (`containment`). The fields are private: outside
/// this library an envelope comes only from [`Envelope::probe`], which
/// reads CPUID itself, so a driver cannot hand `containment` a made-up
/// hypervisor bit or signature.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Envelope {
    /// CPUID.1:ECX bit 31, "hypervisor present".
    hypervisor: bool,
    /// CPUID 0x40000000 EBX, ECX, EDX: the hypervisor's vendor signature.
    vendor: [u8; 12],
    /// Configuration dword 0 of 00:00.0 (device << 16 | vendor).
    host_bridge: u32,
}

impl Envelope {
    /// CPUID leaf 1 ECX[31] and, when set, leaf 4000_0000h's signature, read
    /// here; `host_bridge` is 00:00.0's configuration dword 0 (the caller
    /// reads PCI configuration space). Non-x86_64 builds report no
    /// hypervisor.
    pub fn probe(host_bridge: u32) -> Envelope {
        #[cfg(target_arch = "x86_64")]
        let (hypervisor, vendor) = {
            use core::arch::x86_64::__cpuid;
            let hypervisor = __cpuid(1).ecx & (1 << 31) != 0;
            let mut vendor = [0u8; 12];
            if hypervisor {
                let leaf = __cpuid(0x4000_0000);
                vendor[..4].copy_from_slice(&leaf.ebx.to_le_bytes());
                vendor[4..8].copy_from_slice(&leaf.ecx.to_le_bytes());
                vendor[8..].copy_from_slice(&leaf.edx.to_le_bytes());
            }
            (hypervisor, vendor)
        };
        #[cfg(not(target_arch = "x86_64"))]
        let (hypervisor, vendor) = (false, [0u8; 12]);
        Envelope {
            hypervisor,
            vendor,
            host_bridge,
        }
    }

    /// A hand-built envelope, for host tests only.
    #[cfg(test)]
    pub(crate) fn for_test(hypervisor: bool, vendor: [u8; 12], host_bridge: u32) -> Envelope {
        Envelope {
            hypervisor,
            vendor,
            host_bridge,
        }
    }

    pub fn hypervisor(&self) -> bool {
        self.hypervisor
    }

    pub fn vendor(&self) -> [u8; 12] {
        self.vendor
    }

    pub fn host_bridge(&self) -> u32 {
        self.host_bridge
    }
}

/// Why live DMA is refused outside the declared envelope.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Uncontained {
    /// No hypervisor: a physical boot. ABSD programs no IOMMU, so nothing
    /// confines the device's DMA (#111: no ABSD-uncontained physical DMA).
    NoHypervisor,
    /// A hypervisor other than KVM.
    Vendor([u8; 12]),
    /// A host bridge other than QEMU q35's MCH (8086:29c0).
    HostBridge(u32),
    /// No PCI Express capability within checked bounds, so Device Control
    /// cannot be read.
    NoExpressCapability,
    /// PCIe Device Control enables Relaxed Ordering (bit 4) or No Snoop
    /// (bit 11): the order and coherency the OWN-clear inspection argument
    /// rests on are not shown (re-review 3). The value is kept.
    Ordering(u16),
}

/// PCIe Device Control: Enable Relaxed Ordering (bit 4), Enable No Snoop
/// (bit 11).
pub const DEVCTL_RELAXED_ORDERING: u16 = 1 << 4;
pub const DEVCTL_NO_SNOOP: u16 = 1 << 11;

/// The PCI Express capability's Device Control register, found by the same
/// checked walk as `admit` (aligned, at or above 0x40, no loops) and read
/// only if the whole register lies inside conventional configuration space.
/// Reads only.
pub fn express_device_control(mut read: impl FnMut(u8) -> u32) -> Result<u16, Uncontained> {
    let at = device_control_offset(&mut read)?;
    Ok(read(at) as u16)
}

/// The configuration offset of PCIe Device Control (capability + 8), found
/// by the checked walk.
pub fn device_control_offset(mut read: impl FnMut(u8) -> u32) -> Result<u8, Uncontained> {
    let mut offset = (read(0x34) & 0xff) as u8;
    let mut seen = 0u64;
    while offset != 0 {
        if offset < 0x40 || offset & 3 != 0 {
            return Err(Uncontained::NoExpressCapability);
        }
        let bit = 1u64 << (offset / 4);
        if seen & bit != 0 {
            return Err(Uncontained::NoExpressCapability);
        }
        seen |= bit;
        let header = read(offset);
        if header as u8 == 0x10 {
            // Device Control is the low half of the dword at +8.
            let at = usize::from(offset) + 8;
            if at + 2 > 0x100 {
                return Err(Uncontained::NoExpressCapability);
            }
            return Ok(at as u8);
        }
        offset = (header >> 8) as u8;
    }
    Err(Uncontained::NoExpressCapability)
}

/// The dword to write at Device Control's offset to disable Relaxed
/// Ordering and No Snoop: every other Device Control bit as read, and zero
/// in the upper half, Device Status, whose bits are write-one-to-clear, so
/// none of them is cleared.
pub fn ordering_cleared(dword: u32) -> u32 {
    u32::from(dword as u16 & !(DEVCTL_RELAXED_ORDERING | DEVCTL_NO_SNOOP))
}

/// What `disable_ordering` saw and did.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct OrderingChange {
    pub offset: u8,
    pub before: u16,
    /// Read back after the write (equal to `before` if nothing was written).
    pub after: u16,
    pub written: bool,
}

/// Owner decision on #109 (comment 6528357691): the driver itself disables
/// Relaxed Ordering (and No Snoop, if set) before DMA. Device Control is
/// found by the checked walk, rewritten only if either bit is set (all
/// other bits preserved), and read back; the read-back value must pass
/// `ordering`. Under VFIO the write and the read-back are the guest's view;
/// whether the physical register followed is checked outside (the run
/// harness reads it before allowing the arm).
pub fn disable_ordering(
    mut read: impl FnMut(u8) -> u32,
    mut write: impl FnMut(u8, u32),
) -> Result<OrderingChange, Uncontained> {
    let offset = device_control_offset(&mut read)?;
    let dword = read(offset);
    let before = dword as u16;
    let written = ordering(before).is_err();
    if written {
        write(offset, ordering_cleared(dword));
    }
    let after = read(offset) as u16;
    ordering(after)?;
    Ok(OrderingChange {
        offset,
        before,
        after,
        written,
    })
}

/// DMA is admitted only with Relaxed Ordering and No Snoop both disabled.
pub fn ordering(device_control: u16) -> Result<(), Uncontained> {
    if device_control & (DEVCTL_RELAXED_ORDERING | DEVCTL_NO_SNOOP) == 0 {
        Ok(())
    } else {
        Err(Uncontained::Ordering(device_control))
    }
}

/// KVM's CPUID signature.
pub const KVM_SIGNATURE: [u8; 12] = *b"KVMKVMKVM\0\0\0";
/// QEMU q35 MCH, as reference_host's `absd-vfio-guest` (`-machine q35`) presents it.
pub const Q35_HOST_BRIDGE: u32 = 0x29c0_8086;

/// The only envelope in which `net-rtl8125` and the DMA modes may set bus
/// mastering: a KVM guest on QEMU q35, i.e. reference_host's VFIO launcher. This
/// checks that the expected compatibility signals of such a VM are
/// observed; it does not authenticate the hypervisor (a hostile or emulated
/// platform can present the same signals). It does not, and cannot from
/// inside the guest, check that the host's IOMMU actually confines the
/// passed-through function; that remains the declared external
/// precondition, and the evidence label is reference_host-vfio. There is no option
/// that skips this check. On success it returns the [`VmEnvelopeObserved`]
/// `dma::arm_in_vm` requires for `dma_policy::RTL8125`; nothing else makes
/// one.
pub fn containment(envelope: &Envelope) -> Result<VmEnvelopeObserved, Uncontained> {
    if !envelope.hypervisor {
        return Err(Uncontained::NoHypervisor);
    }
    if envelope.vendor != KVM_SIGNATURE {
        return Err(Uncontained::Vendor(envelope.vendor));
    }
    if envelope.host_bridge != Q35_HOST_BRIDGE {
        return Err(Uncontained::HostBridge(envelope.host_bridge));
    }
    Ok(VmEnvelopeObserved::checked())
}

#[cfg(test)]
mod tests {
    #[test]
    fn only_a_kvm_guest_on_q35_is_inside_the_envelope() {
        let inside = Envelope {
            hypervisor: true,
            vendor: *b"KVMKVMKVM\0\0\0",
            host_bridge: 0x29c0_8086,
        };
        assert_eq!(containment(&inside), Ok(VmEnvelopeObserved::checked()));
        // A physical boot: the hypervisor bit is clear whatever else reads.
        assert_eq!(
            containment(&Envelope {
                hypervisor: false,
                ..inside
            }),
            Err(Uncontained::NoHypervisor)
        );
        // Other hypervisors and machines are outside the declared envelope.
        for vendor in [*b"TCGTCGTCGTCG", *b"Microsoft Hv", [0; 12]] {
            assert_eq!(
                containment(&Envelope { vendor, ..inside }),
                Err(Uncontained::Vendor(vendor))
            );
        }
        for bridge in [0x1237_8086, 0x1630_1022, u32::MAX, 0] {
            assert_eq!(
                containment(&Envelope {
                    host_bridge: bridge,
                    ..inside
                }),
                Err(Uncontained::HostBridge(bridge))
            );
        }
    }

    use super::*;

    /// reference_host's 02:00.0 as OVMF hands it to the guest: I/O BAR0, 64-bit
    /// BAR2 at 0x3800_0000_0000, bus mastering on; PM, MSI, PCIe, MSI-X.
    fn config() -> [u32; 64] {
        let mut c = [0; 64];
        c[0] = 0x812510ec;
        c[1] = 0x0010_0007;
        c[2] = 0x02000005;
        c[4] = 0x6001;
        c[6] = 0x0000_0004;
        c[7] = 0x0000_3800;
        c[8] = 0x0001_0004;
        c[9] = 0x0000_3800;
        c[0x34 / 4] = 0x40;
        c[0x40 / 4] = 0x0350_5001;
        c[0x44 / 4] = 0x0000_0008;
        c[0x50 / 4] = 0x0080_7005;
        c[0x70 / 4] = 0x0002_b010;
        c[0xb0 / 4] = 0x001f_0011;
        c
    }

    fn check(c: [u32; 64]) -> Result<Admitted, Refusal> {
        admit(|offset| c[usize::from(offset / 4)])
    }

    #[test]
    fn reference_host_function_is_admitted_with_its_inherited_command() {
        assert_eq!(
            check(config()),
            Ok(Admitted {
                bar: 0x3800_0000_0000,
                command: 0x0007,
                revision: 5,
            })
        );
    }

    #[test]
    fn identity_class_header_and_bar_refusals() {
        for id in [0xffffffff, 0x816810ec, 0x812610ec, 0x81251234, 0x15b78086] {
            let mut c = config();
            c[0] = id;
            assert_eq!(check(c), Err(Refusal::Identity));
        }
        let mut c = config();
        c[2] = 0x02800005;
        assert_eq!(check(c), Err(Refusal::Class));
        let mut c = config();
        c[3] = 0x80 << 16 | 1 << 16;
        assert_eq!(check(c), Err(Refusal::Header));
        // I/O, 32-bit memory, unassigned, misaligned, all-ones.
        for (low, high) in [
            (0x6001, 0),
            (0xf700_0000, 0),
            (0x4, 0),
            (0x8004, 0x3800),
            (0xffff_fff4, 0xffff_ffff),
        ] {
            let mut c = config();
            c[6] = low;
            c[7] = high;
            assert_eq!(check(c), Err(Refusal::Bar), "{low:#x} {high:#x}");
        }
        // A 64 KiB-aligned BAR below 4 GiB is fine.
        let mut c = config();
        c[6] = 0xfe01_0004;
        c[7] = 0;
        assert_eq!(check(c).map(|a| a.bar), Ok(0xfe01_0000));
    }

    #[test]
    fn decode_and_mastering_are_reported_not_refused() {
        for command in [0x0000, 0x0002, 0x0004, 0x0406] {
            let mut c = config();
            c[1] = 0x0010_0000 | command;
            assert_eq!(check(c).map(|a| a.command), Ok(command as u16));
        }
    }

    #[test]
    fn power_interrupt_and_capability_refusals() {
        for state in 1..=3 {
            let mut c = config();
            c[0x44 / 4] = state;
            assert_eq!(check(c), Err(Refusal::PowerState));
        }
        let mut c = config();
        c[0x50 / 4] |= 1 << 16;
        assert_eq!(check(c), Err(Refusal::InterruptMode));
        let mut c = config();
        c[0xb0 / 4] |= 1 << 31;
        assert_eq!(check(c), Err(Refusal::InterruptMode));
        for pointer in [0, 0x3c, 0x41, 0xff] {
            let mut c = config();
            c[0x34 / 4] = pointer;
            assert_eq!(check(c), Err(Refusal::Capabilities));
        }
        // A loop back to the first capability.
        let mut c = config();
        c[0xb0 / 4] = 0x001f_4011;
        assert_eq!(check(c), Err(Refusal::Capabilities));
        let mut c = config();
        c[1] &= !(1 << 20);
        assert_eq!(check(c), Err(Refusal::Capabilities));
        // No power management capability at all.
        let mut c = config();
        c[0x34 / 4] = 0x50;
        assert_eq!(check(c), Err(Refusal::Capabilities));
    }

    /// Re-review 3: Device Control is found through a checked capability
    /// walk, and Relaxed Ordering or No Snoop refuses DMA.
    #[test]
    fn device_control_is_read_with_checked_bounds_and_gates_ordering() {
        use std::collections::BTreeMap;
        extern crate std;
        let space = |pairs: &[(u8, u32)]| {
            let map: BTreeMap<u8, u32> = pairs.iter().copied().collect();
            move |offset: u8| map.get(&offset).copied().unwrap_or(0)
        };
        // reference_host's chain: PM 0x40 -> MSI 0x50 -> PCIe 0x70 -> 0xb0 -> end.
        let reference_host = [
            (0x34, 0x40),
            (0x40, 0x5001),
            (0x50, 0x7005),
            (0x70, 0xb010),
            (0x78, 0x0010_2017),
            (0xb0, 0x0011),
        ];
        assert_eq!(express_device_control(space(&reference_host)), Ok(0x2017));
        assert_eq!(ordering(0x2017), Err(Uncontained::Ordering(0x2017)));
        assert_eq!(ordering(0x2007), Ok(()));
        assert_eq!(ordering(0x2807), Err(Uncontained::Ordering(0x2807)));
        assert_eq!(ordering(0x0000), Ok(()));
        // No PCIe capability, a loop, a misaligned link, and a capability
        // whose Device Control would fall outside configuration space.
        for bad in [
            &[(0x34, 0x40), (0x40, 0x0001)][..],
            &[(0x34, 0x40), (0x40, 0x4001)][..],
            &[(0x34, 0x42)][..],
            &[(0x34, 0xfc), (0xfc, 0x0010)][..],
            // Device Control at 0x100: outside, and a u8 offset would wrap
            // to the vendor/device dword at 0.
            &[(0x34, 0xf8), (0xf8, 0x0010), (0x00, 0x8125_10ec)][..],
        ] {
            assert_eq!(
                express_device_control(space(bad)),
                Err(Uncontained::NoExpressCapability),
                "{bad:x?}"
            );
        }
        // The last offset whose Device Control still fits.
        assert_eq!(
            express_device_control(space(&[(0x34, 0xf4), (0xf4, 0x0010), (0xfc, 0x0007)])),
            Ok(0x0007)
        );
    }

    /// Owner option 1: only bits 4 and 11 change, the status half is
    /// written as zero (RW1C), the value is read back, and a write that does
    /// not take (VFIO not passing it through) refuses.
    #[test]
    fn ordering_is_disabled_by_read_modify_write_with_read_back() {
        extern crate std;
        use std::cell::RefCell;
        use std::collections::BTreeMap;
        use std::vec::Vec;
        // reference_host: PCIe cap at 0x70, Device Control 0x203f, status 0x0010.
        let base: BTreeMap<u8, u32> = [
            (0x34, 0x40),
            (0x40, 0x5001),
            (0x50, 0x7005),
            (0x70, 0xb010),
            (0x78, 0x0010_203f),
            (0xb0, 0x0011),
        ]
        .into_iter()
        .collect();
        assert_eq!(ordering_cleared(0x0010_203f), 0x0000_202f);
        assert_eq!(ordering_cleared(0xffff_ffff), 0x0000_f7ef);
        assert_eq!(ordering_cleared(0x0000_0807), 0x0000_0007);
        for takes in [true, false] {
            let space = RefCell::new(base.clone());
            let writes = RefCell::new(Vec::new());
            let got = disable_ordering(
                |o| space.borrow().get(&o).copied().unwrap_or(0),
                |o, v| {
                    writes.borrow_mut().push((o, v));
                    if takes {
                        // Device Status is RW1C: writing zero keeps it.
                        let old = space.borrow()[&o];
                        space
                            .borrow_mut()
                            .insert(o, (old & 0xffff_0000) | (v & 0xffff));
                    }
                },
            );
            assert_eq!(*writes.borrow(), [(0x78, 0x0000_202f)]);
            if takes {
                assert_eq!(
                    got,
                    Ok(OrderingChange {
                        offset: 0x78,
                        before: 0x203f,
                        after: 0x202f,
                        written: true
                    })
                );
                assert_eq!(space.borrow()[&0x78], 0x0010_202f, "status kept");
            } else {
                assert_eq!(got, Err(Uncontained::Ordering(0x203f)));
            }
        }
        // Already clear: nothing is written.
        let mut clear = base.clone();
        clear.insert(0x78, 0x0000_202f);
        let mut wrote = false;
        let got = disable_ordering(|o| clear.get(&o).copied().unwrap_or(0), |_, _| wrote = true);
        assert!(!wrote);
        assert_eq!(got.map(|c| c.written), Ok(false));
    }
}
