//! Independent ring-3 workload: protected A, exhausting B, or lifecycle control.
#![no_std]
#![no_main]
#[path = "../reservation_fixture.rs"]
#[allow(dead_code)]
mod fixture;
use absd_user::{Cell, Error, MultiStart, map, unmap};
use fixture::*;
absd_user::multi_entry!(main);

fn main(start: MultiStart<'_>) -> i32 {
    // Exact vector used by the preactivation-abort qualification. A normal
    // activation must change the witness even with duplicate/console copies.
    if let [raw, duplicate, console] = start.handles {
        let cell = Cell::from_raw(*raw);
        if *console != start.console.raw()
            || cell.read() != Cell::from_raw(*duplicate).read()
            || set(cell, 80).is_err()
        {
            return 95;
        }
        return 0;
    }
    let [raw] = start.handles else {
        return 91;
    };
    let cell = Cell::from_raw(*raw);
    let Ok((_, role)) = cell.read() else {
        return 92;
    };
    match run(cell, role) {
        Ok(code) => code,
        Err(_) => {
            let _ = set(cell, 999);
            93
        }
    }
}
fn run(cell: Cell, role: u64) -> Result<i32, Error> {
    match role {
        1 => {
            set(cell, 10)?;
            until(cell, 100)?;
            let mut chunks = [core::ptr::null_mut(); 8];
            for p in &mut chunks {
                match map(64) {
                    Ok(page) => {
                        touch(page, 64);
                        *p = page;
                    }
                    Err(Error::NoMemory) => {
                        set(cell, 12)?;
                        return Ok(12);
                    }
                    Err(e) => return Err(e),
                }
            }
            grow_stack();
            for page in chunks {
                unmap(page, 64)?;
            }
            // Freed reservation credit becomes usable again while B still holds the pool.
            for _ in 0..8 {
                touch(map(64)?, 64);
            }
            let total = call(QUERY, 2, 0, 0);
            while call(QUERY, 0, 0, 0) < total {
                let before = call(QUERY, 0, 0, 0);
                match map(1) {
                    Ok(p) => touch(p, 1),
                    Err(Error::NoMemory) if call(QUERY, 0, 0, 0) == total => break,
                    Err(e) => return Err(e),
                }
                if call(QUERY, 0, 0, 0) <= before {
                    return Err(Error::Invalid);
                }
            }
            if call(QUERY, 0, 0, 0) != 640 || map(1) != Err(Error::NoMemory) {
                return Err(Error::Invalid);
            }
            set(cell, 11)?;
            until(cell, 300)?;
        }
        2 => {
            set(cell, 20)?;
            until(cell, 200)?;
            let refused = call(ADMIT, 65536, 0, 0);
            if refused != -12 && refused != -38 {
                return Err(Error::Invalid);
            }
            let mut pages = 0;
            loop {
                match map(64) {
                    Ok(p) => {
                        touch(p, 64);
                        pages += 64;
                    }
                    Err(Error::NoMemory) => break,
                    Err(e) => return Err(e),
                }
                if pages > 8192 {
                    return Err(Error::Invalid);
                }
            }
            while let Ok(p) = map(1) {
                touch(p, 1);
                pages += 1;
                if pages > 8192 {
                    return Err(Error::Invalid);
                }
            }
            for _ in 0..3 {
                if map(1) != Err(Error::NoMemory) {
                    return Err(Error::Invalid);
                }
            }
            // Full process table refuses before attempting frame admission.
            if absd_user::spawn(absd_user::program::SLEEPER) != Err(Error::Again) {
                return Err(Error::Invalid);
            }
            set(cell, 21 | (pages << 16))?;
            until(cell, 220)?;
            // Supervisor frees one actual process slot. Consume its returned
            // uncommitted frames, then check the independent memory refusal.
            loop {
                match map(1) {
                    Ok(p) => {
                        touch(p, 1);
                        pages += 1;
                    }
                    Err(Error::NoMemory) => break,
                    Err(e) => return Err(e),
                }
                if pages > 8192 {
                    return Err(Error::Invalid);
                }
            }
            for _ in 0..3 {
                if map(1) != Err(Error::NoMemory) {
                    return Err(Error::Invalid);
                }
            }
            if absd_user::spawn(absd_user::program::SLEEPER) != Err(Error::NoMemory) {
                return Err(Error::Invalid);
            }
            set(cell, 22 | (pages << 16))?;
            until(cell, 300)?;
        }
        3 => {
            touch(map(8)?, 8);
        }
        4 => {
            set(cell, 40)?;
            until(cell, 300)?;
        }
        5 => {
            touch(map(8)?, 8);
            unsafe {
                core::arch::asm!("ud2", options(noreturn));
            }
        }
        6 => {
            if call(SPAWN, absd_user::program::SLEEPER, 64, 0) != -1
                || call(SPAWN_IMAGE, 1, 0, 64) != -1
                || (call(QUERY, 3, 0, 0) & 2 != 0 && call(ABORT_IMAGE, 1, 0, 64) != -1)
            {
                return Err(Error::Invalid);
            }
        }
        7 => {
            while let Ok(p) = map(1) {
                touch(p, 1);
            }
            grow_stack();
            return Err(Error::Invalid);
        }
        _ => return Err(Error::Invalid),
    }
    Ok(0)
}
#[inline(never)]
fn grow_stack() {
    unsafe {
        core::arch::asm!(
            "mov r11, rsp", "mov ecx, 12", "2:", "sub rsp, 4096",
            "mov qword ptr [rsp], rcx", "loop 2b", "mov rsp, r11",
            lateout("rcx") _, lateout("r11") _,
        );
    }
}
