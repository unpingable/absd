use super::*;
use absd_kernel::display::{DisplayState, default_geometry};
use absd_kernel::user_memory::{check_user_range, copy_from_user, copy_to_user};

static mut STATE: DisplayState = DisplayState::new_const();
static mut FAULT_ALLOWED: bool = false;

pub(super) unsafe fn state() -> &'static mut DisplayState {
    unsafe { &mut *core::ptr::addr_of_mut!(STATE) }
}

pub fn set_fault_allowed(allowed: bool) {
    unsafe {
        core::ptr::write_volatile(core::ptr::addr_of_mut!(FAULT_ALLOWED), allowed);
    }
}

fn fault_allowed() -> bool {
    unsafe { core::ptr::read_volatile(core::ptr::addr_of!(FAULT_ALLOWED)) }
}

fn effect_result(result: Result<(), i64>) -> i64 {
    match result {
        Ok(()) => 0,
        Err(error) => error,
    }
}

pub(super) unsafe fn call(current: usize, number: u64, a: u64, b: u64, c: u64) -> i64 {
    let table = unsafe { table() };
    let pid = table.entries[current].pid;
    let space = table.entries[current].address_space;
    match number {
        0x7fd0 => {
            if a != 0 || b != 0 || c != 0 {
                return ERROR_INVALID;
            }
            let ready = crate::framebuffer::summary()
                .is_some_and(|summary| summary.geometry == default_geometry());
            match unsafe { state().open(&mut table.entries[current].handles, pid, ready) } {
                Ok(handle) => {
                    crate::framebuffer::clear();
                    handle as i64
                }
                Err(error) => error,
            }
        }
        0x7fd1 => {
            if c != 0 {
                return ERROR_INVALID;
            }
            let record = match unsafe { state().info(&table.entries[current].handles, a) } {
                Ok(record) => record,
                Err(error) => return error,
            };
            if unsafe { copy_to_user(&space, b, &record) }.is_err() {
                return ERROR_FAULT;
            }
            0
        }
        0x7fd2 => {
            let mut snapshot = [0u8; 48];
            if unsafe { copy_from_user(&space, b, &mut snapshot) }.is_err() {
                return ERROR_FAULT;
            }
            let request = match absd_kernel::display::request_snapshot(&snapshot) {
                Ok(request) => request,
                Err(error) => return error,
            };
            effect_result(unsafe {
                state().present(
                    &table.entries[current].handles,
                    a,
                    request,
                    crate::framebuffer::write_rect,
                    |length| check_user_range(&space, c, length, false),
                    |destination| copy_from_user(&space, c, destination),
                )
            })
        }
        0x7fd3 => {
            let result = unsafe { state().mask(&table.entries[current].handles, a, b, c) };
            if result.is_ok() {
                crate::framebuffer::clear();
            }
            effect_result(result)
        }
        0x7fd4 => effect_result(unsafe {
            state().console_restore(&table.entries[current].handles, a, b, c)
        }),
        0x7fdf => {
            if c != 0 {
                return ERROR_INVALID;
            }
            if let Err(error) = unsafe {
                state().fault_fixture(
                    &table.entries[current].handles,
                    a,
                    b,
                    fault_allowed(),
                    !crate::framebuffer::drawing_active(),
                )
            } {
                return error;
            }
            unsafe { crate::trigger_page_fault() };
            0
        }
        _ => ERROR_NOT_IMPLEMENTED,
    }
}
