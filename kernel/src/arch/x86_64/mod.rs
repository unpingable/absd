//! Small x86_64 descriptor encodings used by the boot-time exception path.

pub const TSS_SELECTOR: u16 = 0x18;
pub const DOUBLE_FAULT_IST: u16 = 1;
pub const TSS_SIZE: u32 = 104;
pub const USER_CODE_SELECTOR: u64 = 0x2b;
pub const USER_DATA_SELECTOR: u64 = 0x33;

/// A GDTR is an identity anchor only after its independently checked CPU
/// installation. This decoder establishes geometry, never CPU authority.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CpuAnchor {
    Unknown,
    Invalid,
    Cpu(u8),
}

#[inline(always)] // The kernel caller disables the red zone; preserve that boundary.
#[allow(clippy::too_many_arguments)] // Three fixed descriptor geometries and admission bounds.
pub fn cpu_anchor(
    base: u64,
    limit: u16,
    bsp: u64,
    ap: u64,
    stride: u64,
    legacy: u64,
    count: usize,
    maximum: usize,
) -> CpuAnchor {
    if base == bsp {
        return if limit == 55 {
            CpuAnchor::Cpu(0)
        } else {
            CpuAnchor::Invalid
        };
    }
    for (start, step, expected_limit) in [(ap, stride, 55), (legacy, 40, 39)] {
        if base >= start && base - start < step * (maximum - 1) as u64 {
            let delta = base - start;
            let index = delta / step + 1;
            return if delta.is_multiple_of(step) && limit == expected_limit && index < count as u64
            {
                CpuAnchor::Cpu(index as u8)
            } else {
                CpuAnchor::Invalid
            };
        }
    }
    CpuAnchor::Unknown
}

/// IA32_APIC_BASE bit 8 is set only on the bootstrap processor.
pub const fn apic_base_is_bsp(low: u32) -> bool {
    low & (1 << 8) != 0
}

pub const fn interrupt_gate_options(ist: u16) -> u16 {
    0x8e00 | (ist & 0x7)
}

/// Encodes the two GDT slots for an available 64-bit TSS descriptor.
pub const fn tss_descriptor(base: u64, limit: u32) -> [u64; 2] {
    let low = (limit as u64 & 0xffff)
        | ((base & 0x00ff_ffff) << 16)
        | (0x89u64 << 40)
        | ((limit as u64 & 0x000f_0000) << 48)
        | ((base & 0xff00_0000) << 32);
    [low, base >> 32]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cpu_anchor_requires_exact_geometry_and_admission() {
        let decode = |base, limit, count| cpu_anchor(base, limit, 1000, 2000, 256, 4000, count, 6);
        assert_eq!(decode(1000, 55, 6), CpuAnchor::Cpu(0));
        for id in 1..6 {
            assert_eq!(
                decode(2000 + (id - 1) * 256, 55, 6),
                CpuAnchor::Cpu(id as u8)
            );
            assert_eq!(
                decode(4000 + (id - 1) * 40, 39, 6),
                CpuAnchor::Cpu(id as u8)
            );
        }
        for (base, limit, count) in [
            (1000, 39, 6),
            (2001, 55, 6),
            (2000, 39, 6),
            (2256, 55, 2),
            (4001, 39, 6),
            (4000, 55, 6),
        ] {
            assert_eq!(decode(base, limit, count), CpuAnchor::Invalid);
        }
        assert_eq!(decode(999, 55, 6), CpuAnchor::Unknown);
    }

    #[test]
    fn double_fault_gate_selects_ist_one() {
        assert_eq!(interrupt_gate_options(DOUBLE_FAULT_IST), 0x8e01);
    }

    #[test]
    fn tss_descriptor_keeps_base_limit_and_type() {
        let [low, high] = tss_descriptor(0x1234_5678_9abc_def0, TSS_SIZE - 1);
        assert_eq!(low & 0xffff, (TSS_SIZE - 1) as u64);
        assert_eq!((low >> 40) & 0xff, 0x89);
        assert_eq!(high, 0x1234_5678);
    }

    #[test]
    fn user_selectors_are_ring_three_gdt_entries() {
        assert_eq!(USER_CODE_SELECTOR & 3, 3);
        assert_eq!(USER_DATA_SELECTOR & 3, 3);
        assert_eq!(USER_CODE_SELECTOR >> 3, 5);
        assert_eq!(USER_DATA_SELECTOR >> 3, 6);
    }

    #[test]
    fn apic_base_refuses_application_processor_identity() {
        assert!(apic_base_is_bsp(0xfee0_0900));
        assert!(!apic_base_is_bsp(0xfee0_0800));
    }
}

use crate::process::MAX_USER_PAGE_TABLES;
pub const ELF_MACHINE: u16 = 62;
pub type ExecutionContext = [u64; 20];
pub const EMPTY_CONTEXT: ExecutionContext = [0; 20];
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PageTableSlot {
    pub directory_index: usize,
    pub frame: u64,
}

impl PageTableSlot {
    pub const EMPTY: Self = Self {
        directory_index: usize::MAX,
        frame: 0,
    };
}

/// Physical frames exclusively owned by one process's page-table hierarchy.
/// `root` also references the shared kernel PDPT, which is never owned here.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AddressSpace {
    pub root: u64,
    pub pdpt: u64,
    pub directory: u64,
    pub page_tables: [PageTableSlot; MAX_USER_PAGE_TABLES],
}

impl AddressSpace {
    pub const EMPTY: Self = Self {
        root: 0,
        pdpt: 0,
        directory: 0,
        page_tables: [PageTableSlot::EMPTY; MAX_USER_PAGE_TABLES],
    };
}

/// FXSAVE/FXRSTOR image: x87 control/status, MXCSR, and XMM0–XMM15.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(C, align(16))]
pub struct FpuState(pub [u8; 512]);

impl FpuState {
    /// x87 control word 0x37f and MXCSR 0x1f80: all exceptions masked,
    /// round to nearest, the state a fresh process expects.
    pub const INITIAL: Self = {
        let mut bytes = [0u8; 512];
        bytes[0] = 0x7f;
        bytes[1] = 0x03;
        bytes[24] = 0x80;
        bytes[25] = 0x1f;
        Self(bytes)
    };
}

impl crate::arch::ExecutionState for ExecutionContext {
    fn argument(&self, index: usize) -> u64 {
        self[[10, 11, 12, 13, 9][index]]
    }
    fn set_argument(&mut self, index: usize, value: u64) {
        self[[10, 11, 12, 13, 9][index]] = value;
    }
    fn set_stack(&mut self, value: u64) {
        self[18] = value;
    }
    fn set_result(&mut self, value: i64) {
        self[14] = value as u64;
    }
}

pub const USER_RED_ZONE: u64 = 128;
pub fn memory_fault(error: u64) -> crate::arch::MemoryFault {
    use crate::arch::{Access, FaultClass, MemoryFault};
    MemoryFault {
        class: if error & !0x17 != 0 {
            FaultClass::Other
        } else if error & 1 == 0 {
            FaultClass::Translation
        } else {
            FaultClass::Permission
        },
        access: if error & 16 != 0 {
            Access::Execute
        } else if error & 2 != 0 {
            Access::Write
        } else {
            Access::Read
        },
        from_user: error & 4 != 0,
    }
}

/// Called only by a ring-3 exception entry. #GP cannot identify alignment.
pub fn normalize_user_exception(vector: u64, error: u64, address: u64) -> crate::arch::UserFault {
    use crate::arch::{FaultClass, UserFault};
    if vector == 14 {
        let m = memory_fault(error);
        UserFault {
            class: m.class,
            access: Some(m.access),
            from_user: m.from_user,
            address,
        }
    } else {
        UserFault {
            class: match vector {
                6 => FaultClass::Undefined,
                17 => FaultClass::Alignment,
                16 | 19 => FaultClass::FloatingPoint,
                _ => FaultClass::Other,
            },
            access: None,
            from_user: true,
            address,
        }
    }
}
#[cfg(test)]
mod fault_tests {
    use super::*;
    use crate::arch::{Access, FaultClass};
    #[test]
    fn native_fault_classification_keeps_nx_and_reserved_bits_distinct() {
        let nx = normalize_user_exception(14, 0x15, 0x1000);
        assert_eq!(nx.class, FaultClass::Permission);
        assert_eq!(nx.access, Some(Access::Execute));
        assert!(nx.from_user);
        assert_eq!(memory_fault(0x1d).class, FaultClass::Other);
        assert_eq!(memory_fault(4).class, FaultClass::Translation);
        assert_eq!(
            normalize_user_exception(6, 0, 1).class,
            FaultClass::Undefined
        );
        assert_eq!(normalize_user_exception(13, 0, 1).class, FaultClass::Other);
        assert_eq!(
            normalize_user_exception(19, 0, 1).class,
            FaultClass::FloatingPoint
        );
    }
}
