//! Actual syscall routing/grant helpers with controlled CPU, memory and devices.
//! This does not exercise page-table validation, hardware, or the scheduler.
//! The table is narrowed to one process; format bytes are controlled here.
//! Actual capacity encoding is tested against its shared golden separately.
#![allow(dead_code)]
extern crate self as absd_kernel;
pub use absd_abi::{program, syscall};
#[path = "../../src/handle.rs"] pub mod handle;
#[path = "../../src/object.rs"] pub mod object;
#[path = "../../src/kernel_log.rs"] pub mod kernel_log;
#[path = "../../src/syscalls/observation.rs"] mod observation_call;
use std::sync::atomic::{AtomicU8, AtomicUsize, Ordering};

static CPU: AtomicU8 = AtomicU8::new(0);
static DEVICES: AtomicUsize = AtomicUsize::new(0);
static MEMORY: AtomicUsize = AtomicUsize::new(0);
mod cpu { pub fn id() -> u8 { super::CPU.load(super::Ordering::Relaxed) } }
mod kernel_lock {
    pub const BSP: u8 = 0;
    pub fn assert_bsp_device_access() { assert_eq!(crate::cpu::id(), BSP, "BSP-only device path reached from AP"); }
}
mod process { pub const KERNEL_PARENT: u64 = 0; pub const MAX_PROCESSES: usize = 1; }
mod sched { pub fn now() -> u64 { 900 } }
pub mod observation {
    pub const BYTES: usize = 256;
    pub const QUERY_NIC: u64 = 256;
    pub const QUERY_CAPACITY: u64 = 257;
    pub fn capacity_record(_: u64) -> [u8; BYTES] { frame(4) }
    pub fn process_record<T>(_: &T, _: u64, _: usize) -> [u8; BYTES] { frame(1) }
    pub fn frame(kind: u64) -> [u8; BYTES] {
        let mut out = [0; BYTES]; out[..8].copy_from_slice(&1u64.to_le_bytes());
        out[8..16].copy_from_slice(&kind.to_le_bytes()); out
    }
}
mod nic_device {
    pub fn observation() -> [u8; crate::observation::BYTES] {
        crate::kernel_lock::assert_bsp_device_access();
        crate::DEVICES.fetch_add(1, crate::Ordering::Relaxed);
        crate::observation::frame(2)
    }
    pub fn candidate_observation(_: usize) -> Option<[u8; crate::observation::BYTES]> {
        crate::kernel_lock::assert_bsp_device_access();
        crate::DEVICES.fetch_add(1, crate::Ordering::Relaxed);
        Some(crate::observation::frame(3))
    }
}
pub mod user_memory {
    pub unsafe fn check_user_range(_: &(), _: u64, bytes: usize, write: bool) -> Result<(), ()> {
        assert_eq!(bytes, 256); assert!(write);
        crate::MEMORY.fetch_add(1, crate::Ordering::Relaxed); Ok(())
    }
    pub unsafe fn copy_to_user(_: &(), address: u64, bytes: &[u8]) -> Result<(), ()> {
        unsafe { core::ptr::copy_nonoverlapping(bytes.as_ptr(), address as *mut u8, bytes.len()); }
        Ok(())
    }
}
struct Process {
    pid: u64, parent: u64, program: usize, address_space: (), handles: handle::HandleTable,
}
struct Table { entries: [Process; 1] }
struct Stats { pointer_refusals: u64 }
static mut TABLE: Option<Table> = None;
static mut STATS: Stats = Stats { pointer_refusals: 0 };
unsafe fn table() -> &'static mut Table {
    unsafe { (&mut *core::ptr::addr_of_mut!(TABLE)).as_mut().unwrap() }
}
unsafe fn stats() -> &'static mut Stats { unsafe { &mut *core::ptr::addr_of_mut!(STATS) } }
unsafe fn handle_error(error: handle::HandleError) -> i64 {
    match error { handle::HandleError::Rights => syscall::ERROR_RIGHTS, _ => syscall::ERROR_INVALID }
}

fn main() {
    let mut handles = handle::HandleTable::new(9);
    let grant = handles.insert(handle::Object::Diagnostics, handle::RIGHT_READ).unwrap();
    assert!(!handles.has_bsp_authority(), "read-only grant must not pin every operator child");
    unsafe { TABLE = Some(Table { entries: [Process {
        pid: 9, parent: 1, program: program::IMAGE as usize, address_space: (), handles,
    }] }); }
    let mut out = [0u8; 256];
    CPU.store(1, Ordering::Relaxed);
    for query in [256, 512, 767] {
        let rc = unsafe { observation_call::read(0, 0, out.as_mut_ptr() as u64, query) };
        assert_eq!(rc, syscall::ERROR_NOT_IMPLEMENTED, "AP device query {query}");
    }
    assert_eq!(DEVICES.load(Ordering::Relaxed), 0);
    assert_eq!(MEMORY.load(Ordering::Relaxed), 0);
    assert_eq!(unsafe { observation_call::read(0, 0, out.as_mut_ptr() as u64, 0) }, 0);
    assert_eq!(unsafe { observation_call::read(0, 0, out.as_mut_ptr() as u64, 257) }, 0);
    assert_eq!(u64::from_le_bytes(out[8..16].try_into().unwrap()), 4);
    assert_eq!(DEVICES.load(Ordering::Relaxed), 0);
    CPU.store(0, Ordering::Relaxed);
    for query in [256, 512] {
        assert_eq!(unsafe { observation_call::read(0, 0, out.as_mut_ptr() as u64, query) }, 0);
    }
    assert_eq!(DEVICES.load(Ordering::Relaxed), 2);
    unsafe { table().entries[0].handles.close(grant).unwrap(); }
    CPU.store(1, Ordering::Relaxed);
    assert_eq!(unsafe { observation_call::read(0, 0, out.as_mut_ptr() as u64, 256) }, syscall::ERROR_RIGHTS);
    println!("DIAGNOSTIC DEVICE ROUTING HOST OK checks=8");
}
