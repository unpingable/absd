//! ARM64 execution state: private to ISA mechanisms, never a transfer ABI.
use crate::process::MAX_USER_PAGE_TABLES;
pub const ELF_MACHINE: u16 = 183;
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
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(C, align(16))]
pub struct FpuState(pub [u8; 528]);
impl FpuState {
    pub const INITIAL: Self = Self([0; 528]);
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(C)]
pub struct ExecutionContext {
    registers: [u64; 31],
    sp: u64,
    pc: u64,
    status: u64,
}
pub const EMPTY_CONTEXT: ExecutionContext = ExecutionContext {
    registers: [0; 31],
    sp: 0,
    pc: 0,
    status: 0,
};
impl ExecutionContext {
    pub fn entry(pc: u64, sp: u64, arguments: [u64; 5]) -> Self {
        let mut frame = EMPTY_CONTEXT;
        frame.pc = pc;
        frame.sp = sp;
        frame.registers[..5].copy_from_slice(&arguments);
        frame
    }
    pub fn syscall(&self) -> (u64, [u64; 3]) {
        (
            self.registers[8],
            [self.registers[0], self.registers[1], self.registers[2]],
        )
    }
    pub fn pc(&self) -> u64 {
        self.pc
    }
    pub fn stack_pointer(&self) -> u64 {
        self.sp
    }
}
const _: () = {
    assert!(core::mem::size_of::<ExecutionContext>() == 272);
    assert!(core::mem::size_of::<FpuState>() == 528);
};

impl crate::arch::ExecutionState for ExecutionContext {
    fn argument(&self, index: usize) -> u64 {
        self.registers[index]
    }
    fn set_argument(&mut self, index: usize, value: u64) {
        self.registers[index] = value;
    }
    fn set_stack(&mut self, value: u64) {
        self.sp = value;
    }
    fn set_result(&mut self, value: i64) {
        self.registers[0] = value as u64;
    }
}
impl ExecutionContext {
    pub fn as_ptr(&self) -> *const u64 {
        (self as *const Self).cast()
    }
}

pub const USER_RED_ZONE: u64 = 0;
pub fn memory_fault(esr: u64) -> crate::arch::MemoryFault {
    use crate::arch::{Access, FaultClass, MemoryFault};
    let ec = esr >> 26;
    let fsc = esr & 63;
    MemoryFault {
        class: match fsc {
            4..=7 => FaultClass::Translation,
            12..=15 => FaultClass::Permission,
            0x21 => FaultClass::Alignment,
            _ => FaultClass::Other,
        },
        access: if ec == 0x20 {
            Access::Execute
        } else if esr & (1 << 6) != 0 {
            Access::Write
        } else {
            Access::Read
        },
        from_user: matches!(ec, 0x20 | 0x24),
    }
}

pub fn normalize_user_exception(vector: u64, error: u64, address: u64) -> crate::arch::UserFault {
    use crate::arch::{FaultClass, UserFault};
    if matches!(vector, 0x20 | 0x24) {
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
                0 => FaultClass::Undefined,
                0x22 | 0x26 => FaultClass::Alignment,
                0x2c => FaultClass::FloatingPoint,
                _ => FaultClass::Other,
            },
            access: None,
            from_user: true,
            address,
        }
    }
}
