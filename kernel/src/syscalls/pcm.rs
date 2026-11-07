//! Private playback calls enabled only in the native PCM experiment build.
//! Open is an init-only root grant, available only after explicit boot probing.
//! Descendants receive authority solely through existing handle transfers.
use super::*;
use crate::virtio_sound as driver;
use absd_kernel::syscall::{ERROR_AGAIN, ERROR_RIGHTS};
static mut OPENED: bool = false;
static mut WRITERS: usize = 0;
pub(super) unsafe fn retain(rights: u8) {
    if rights & RIGHT_WRITE != 0 {
        unsafe {
            WRITERS += 1;
        }
    }
}
pub(super) unsafe fn release(rights: u8) {
    if rights & RIGHT_WRITE != 0 {
        unsafe {
            assert!(WRITERS > 0);
            WRITERS -= 1;
            if WRITERS == 0 {
                driver::cancel();
            }
        }
    }
}
fn error(e: driver::Error) -> i64 {
    match e {
        driver::Error::Full => ERROR_AGAIN,
        driver::Error::Invalid => ERROR_INVALID,
        _ => ERROR_IO,
    }
}
pub(super) unsafe fn call(current: usize, number: u64, a: u64, b: u64, c: u64) -> i64 {
    if number == 0x7fe0 {
        if a != 0 || b != 0 || c != 0 {
            return ERROR_INVALID;
        }
        if unsafe { table() }.entries[current].pid != 1 {
            return ERROR_RIGHTS;
        }
        if unsafe { OPENED } {
            return ERROR_AGAIN;
        }
        if let Err(e) = driver::status() {
            return error(e);
        }
        match unsafe { table() }.entries[current]
            .handles
            .insert(Object::Playback, RIGHT_READ | RIGHT_WRITE)
        {
            Ok(h) => {
                unsafe {
                    OPENED = true;
                    retain(RIGHT_WRITE);
                }
                h as i64
            }
            Err(e) => unsafe { handle_error(e) },
        }
    } else {
        let found = match unsafe { table() }.entries[current].handles.lookup(a) {
            Ok(h) => h,
            Err(e) => return unsafe { handle_error(e) },
        };
        if found.object != Object::Playback {
            return unsafe { handle_error(HandleError::Invalid) };
        }
        if let Err(e) = found.require(if number == 0x7fe2 {
            RIGHT_READ
        } else {
            RIGHT_WRITE
        }) {
            return unsafe { handle_error(e) };
        }
        let space = unsafe { table() }.entries[current].address_space;
        match number {
            0x7fe1 => {
                if c == 0 || c > 1920 || !c.is_multiple_of(4) {
                    return ERROR_INVALID;
                }
                let mut bytes = [0u8; 1920];
                if unsafe { copy_from_user(&space, b, &mut bytes[..c as usize]) }.is_err() {
                    return ERROR_FAULT;
                }
                match driver::submit(&bytes[..c as usize]) {
                    Ok(()) => c as i64,
                    Err(e) => error(e),
                }
            }
            0x7fe2 => {
                if c != 48 {
                    return ERROR_INVALID;
                }
                // Validate before polling or changing device-visible state.
                if unsafe { absd_kernel::user_memory::check_user_range(&space, b, 48, true) }
                    .is_err()
                {
                    return ERROR_FAULT;
                }
                let s = match driver::status() {
                    Ok(s) => s,
                    Err(e) => return error(e),
                };
                let words = [
                    1u64,
                    48000 | (2 << 32) | (16 << 40),
                    s.submitted_frames,
                    s.completed_frames,
                    s.pending as u64,
                    s.latency_bytes as u64 | ((s.running as u64) << 32) | ((s.failed as u64) << 33),
                ];
                let mut bytes = [0u8; 48];
                for (i, w) in words.iter().enumerate() {
                    bytes[i * 8..i * 8 + 8].copy_from_slice(&w.to_le_bytes());
                }
                if unsafe { copy_to_user(&space, b, &bytes) }.is_err() {
                    ERROR_FAULT
                } else {
                    0
                }
            }
            0x7fe3 => {
                if b != 0 || c != 0 {
                    return ERROR_INVALID;
                }
                match driver::stop() {
                    Ok(()) => 0,
                    Err(e) => error(e),
                }
            }
            _ => ERROR_INVALID,
        }
    }
}
