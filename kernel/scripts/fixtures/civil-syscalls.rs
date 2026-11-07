#![allow(dead_code)]
use absd_kernel::syscall::{
    ERROR_BAD_HANDLE, ERROR_FAULT, ERROR_INVALID, ERROR_RIGHTS, ERROR_TOO_MANY_HANDLES,
};
use absd_kernel::{
    civil_clock::{Clock, EventLimiter, Info},
    handle::{HandleError, Object, RIGHT_READ, RIGHT_WRITE},
    process::ProcessTable,
};
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering::Relaxed};
static NOW: AtomicU64 = AtomicU64::new(10);
static READS: AtomicUsize = AtomicUsize::new(0);
static REFUSALS: AtomicUsize = AtomicUsize::new(0);
static mut TABLE: ProcessTable = ProcessTable::new();
static mut CIVIL_CLOCK: Clock = Clock::new();
static mut CLOCK_EVENT_LIMITER: EventLimiter = EventLimiter::new();
fn now() -> u64 {
    NOW.load(Relaxed)
}
unsafe fn table() -> &'static mut ProcessTable {
    unsafe { &mut *core::ptr::addr_of_mut!(TABLE) }
}
unsafe fn count_handle_refusal(_: u64) {
    REFUSALS.fetch_add(1, Relaxed);
}
fn initialize_civil_time() {
    unsafe {
        (&mut *core::ptr::addr_of_mut!(CIVIL_CLOCK)).initialize_rtc_result(Err(-5), 0);
    }
}
fn observe_clock_quality(_: Info) {}
fn clock_event(_: &str, _: Info, _: Info, _: u64) {}
unsafe fn copy_from_user<T>(_: &T, address: u64, out: &mut [u8]) -> Result<(), ()> {
    READS.fetch_add(1, Relaxed);
    if address == 0 {
        return Err(());
    }
    unsafe {
        std::ptr::copy_nonoverlapping(address as *const u8, out.as_mut_ptr(), out.len());
    }
    Ok(())
}
#[test]
fn actual_mint_and_update_enforce_identity_rights_and_no_mutation_on_refusal() {
    println!(
        "COMPILED DEFAULT KERNEL ABI USER_HEAP_PAGES={} USER_IMAGE_MIN={:#x} USER_IMAGE_MAX={:#x}",
        absd_kernel::layout::USER_HEAP_PAGES,
        absd_kernel::layout::USER_IMAGE_MIN,
        absd_kernel::layout::USER_IMAGE_MAX
    );
    unsafe {
        let p = &mut table().entries[0];
        p.pid = 1;
        p.parent = absd_kernel::process::KERNEL_PARENT;
        p.program = absd_kernel::program::INIT as usize;
        p.handles = absd_kernel::handle::HandleTable::new(1);
        let read_console = p.handles.insert(Object::Console, RIGHT_READ).unwrap();
        assert_eq!(civil_mint(0, read_console, 0, 0), ERROR_RIGHTS);
        let console = table().entries[0]
            .handles
            .insert(Object::Console, RIGHT_WRITE)
            .unwrap();
        assert_eq!(civil_mint(0, console, 1, 0), ERROR_INVALID);
        table().entries[0].pid = 2;
        assert_eq!(civil_mint(0, console, 0, 0), ERROR_RIGHTS);
        table().entries[0].pid = 1;
        table().entries[0].parent = 1;
        assert_eq!(civil_mint(0, console, 0, 0), ERROR_RIGHTS);
        table().entries[0].parent = absd_kernel::process::KERNEL_PARENT;
        table().entries[0].program += 1;
        assert_eq!(civil_mint(0, console, 0, 0), ERROR_RIGHTS);
        table().entries[0].program = absd_kernel::program::INIT as usize;
        let handle = civil_mint(0, console, 0, 0);
        assert!(handle >= 0);
        let handle = handle as u64;
        assert_eq!(
            table().entries[0].handles.insert(Object::Clock, RIGHT_READ),
            Err(HandleError::Rights)
        );
        let readonly = table().entries[0].handles.insert(Object::Clock, 0).unwrap();
        READS.store(0, Relaxed);
        assert_eq!(civil_update(0, readonly, 0, 0), ERROR_RIGHTS);
        assert_eq!(READS.load(Relaxed), 0);
        assert_eq!(civil_update(0, console, 0, 0), ERROR_RIGHTS);
        assert_eq!(READS.load(Relaxed), 0);
        assert_eq!(civil_update(0, handle, 0, 1), ERROR_INVALID);
        assert_eq!(READS.load(Relaxed), 0);
        assert_eq!(civil_update(0, handle, 0, 0), ERROR_FAULT);
        assert_eq!(READS.load(Relaxed), 1);
        let mut request = [0u8; 64];
        request[..4].copy_from_slice(&1u32.to_le_bytes());
        request[4] = 1;
        request[8] = 2;
        request[16..24].copy_from_slice(&100_000_000_000u64.to_le_bytes());
        request[24..32].copy_from_slice(&10u64.to_le_bytes());
        assert_eq!(civil_update(0, handle, request.as_ptr() as u64, 0), 0);
        let before = (&*core::ptr::addr_of!(CIVIL_CLOCK)).info(now());
        assert_eq!(before.now_ns, Some(100_000_000_000));
        request[63] = 1;
        assert_eq!(
            civil_update(0, handle, request.as_ptr() as u64, 0),
            ERROR_INVALID
        );
        assert_eq!((&*core::ptr::addr_of!(CIVIL_CLOCK)).info(now()), before);
        table().entries[0].handles.close(handle).unwrap();
        READS.store(0, Relaxed);
        assert_eq!(civil_update(0, handle, 0, 0), ERROR_BAD_HANDLE);
        assert_eq!(READS.load(Relaxed), 0);
        while table().entries[0].handles.live_count() < absd_kernel::handle::MAX_HANDLES {
            table().entries[0].handles.insert(Object::Clock, 0).unwrap();
        }
        assert_eq!(civil_mint(0, console, 0, 0), ERROR_TOO_MANY_HANDLES);
    }
}
