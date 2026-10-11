//! Leaves one child behind so init can prove userspace orphan adoption for
//! both terminal and still-live descendants.
#![no_std]
#![no_main]

use absd_user::{
    Cell, Child, INFO_STATE_LIVE, INFO_STATE_TERMINAL, INFO_STATE_WAITING, Start, info, program,
    spawn, spawn_with, time, yield_now,
};

absd_user::entry!(main);

fn main(start: Start) -> i32 {
    match start.arg {
        // Let exit7 become terminal, but deliberately do not wait for it.
        0 => {
            let Ok(child) = spawn(program::EXIT7) else {
                return 88;
            };
            if !terminal_unreaped(child) {
                return 88;
            }
            0
        }
        // Exit while the sleeping child is still live and still owned here.
        1 => {
            let Ok(child) = spawn_with(program::SLEEPER, 0, 40) else {
                return 89;
            };
            let state = info(Some(child)).map(|record| record.state);
            if state != Ok(INFO_STATE_LIVE) && state != Ok(INFO_STATE_WAITING) {
                return 89;
            }
            0
        }
        // Keep the orphaner alive until init has filled its own handle table.
        // Releasing the read-only control cell makes an already-terminal child
        // adoptable while PID 1 remains at the handle-capacity boundary.
        2 => {
            if start.handle == 0 {
                return 90;
            }
            let Ok(child) = spawn(program::EXIT7) else {
                return 90;
            };
            if !terminal_unreaped(child) {
                return 90;
            }
            match Cell::from_raw(start.handle).wait_change_timeout(0, 1000) {
                Ok(1) => 0,
                _ => 90,
            }
        }
        _ => 87,
    }
}

// A delay does not establish child completion under concurrent scheduling.
// Observe the terminal state without consuming its adoption outcome.
fn terminal_unreaped(child: Child) -> bool {
    let deadline = time().saturating_add(500);
    loop {
        match info(Some(child)) {
            Ok(record) if record.state == INFO_STATE_TERMINAL => return true,
            Ok(record)
                if matches!(record.state, INFO_STATE_LIVE | INFO_STATE_WAITING)
                    && time() < deadline =>
            {
                yield_now()
            }
            _ => return false,
        }
    }
}
