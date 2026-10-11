//! Verifies the ordered multi-handle start vector and composes a narrowed
//! cell handle with either a serial or captured-pipe console.
#![no_std]
#![no_main]

use absd_user::{
    Cell, Error, MultiStart, Outcome, RIGHT_READ, RIGHT_WRITE, SpawnHandleCopy, close, duplicate,
    program, spawn_many_copy, spawn_with, wait_timeout,
};

const RIGHTS_CHAIN_MAX: usize = 8;
const RIGHTS_CHAIN_MIN: usize = 4;
const CONSOLE_PROBE_MARKER: u64 = 0x434f_4e53_4f4c_4501;

absd_user::multi_entry!(main);

fn main(start: MultiStart<'_>) -> i32 {
    match start.handles {
        // Parent side of the console-authority probe: this process receives a
        // write-only global console as its console, then spawns through both
        // ABIs without an explicit console replacement.
        [console] if *console == start.console.raw() => {
            let Ok(legacy) = spawn_with(program::HELLO_B, 0, 1) else {
                return 85;
            };
            if wait_timeout(Some(legacy), 500) != Ok(Outcome::Exited(0)) {
                return 85;
            }
            let Ok(marker_cell) = Cell::create(CONSOLE_PROBE_MARKER) else {
                return 85;
            };
            let marker = [SpawnHandleCopy::new(marker_cell.raw(), RIGHT_READ)];
            let Ok(multi) = spawn_many_copy(program::MULTI_HANDLE, &marker) else {
                return 85;
            };
            if wait_timeout(Some(multi), 500) != Ok(Outcome::Exited(0))
                || close(marker_cell.raw()).is_err()
            {
                return 85;
            }
            0
        }
        // A multi-start child used by the console-authority probe. Its parent
        // holds only write authority, so the default console must not read.
        [marker] => {
            if Cell::from_raw(*marker).read() != Ok((0, CONSOLE_PROBE_MARKER)) {
                return 88;
            }
            match start.console.read_once(&mut [0u8; 1]) {
                Err(Error::Rights) => 0,
                _ => 85,
            }
        }
        // Fuzz-only path invariant: every generation receives read-only cell
        // copies, narrows again locally, and passes fewer copies to the next
        // process. No edge in the duplicate/spawn-copy chain may strengthen
        // rights. Closing and reissuing the local duplicate also pins opaque
        // stale-handle identity across every depth.
        handles if (RIGHTS_CHAIN_MIN..=RIGHTS_CHAIN_MAX).contains(&handles.len()) => {
            for &handle in handles {
                let cell = Cell::from_raw(handle);
                if cell.read().is_err()
                    || cell.transition(0, 1) != Err(Error::Rights)
                    || duplicate(handle, RIGHT_READ | RIGHT_WRITE) != Err(Error::Rights)
                {
                    return 86;
                }
            }

            let Ok(stale) = duplicate(handles[0], RIGHT_READ) else {
                return 86;
            };
            if close(stale).is_err() || Cell::from_raw(stale).read() != Err(Error::BadHandle) {
                return 86;
            }
            let Ok(fresh) = duplicate(handles[0], RIGHT_READ) else {
                return 86;
            };
            if fresh == stale || Cell::from_raw(fresh).read().is_err() {
                return 86;
            }
            if spawn_many_copy(
                program::MULTI_HANDLE,
                &[SpawnHandleCopy::new(fresh, RIGHT_READ | RIGHT_WRITE)],
            ) != Err(Error::Rights)
            {
                return 86;
            }

            if handles.len() > RIGHTS_CHAIN_MIN {
                let mut copies = [SpawnHandleCopy::new(0, 0); RIGHTS_CHAIN_MAX];
                for copy in &mut copies[..handles.len() - 1] {
                    *copy = SpawnHandleCopy::new(fresh, RIGHT_READ);
                }
                let Ok(child) =
                    spawn_many_copy(program::MULTI_HANDLE, &copies[..handles.len() - 1])
                else {
                    return 86;
                };
                if close(fresh).is_err() || wait_timeout(Some(child), 500) != Ok(Outcome::Exited(0))
                {
                    return 86;
                }
            } else if close(fresh).is_err() {
                return 86;
            }
            0
        }
        // Milestone 1 probe: independent read-only and write-only views of
        // one cell, plus a console replacement, all preserve input order.
        [read, write, console] if *console == start.console.raw() => {
            let reader = Cell::from_raw(*read);
            let writer = Cell::from_raw(*write);
            let Ok((version, value)) = reader.read() else {
                return 88;
            };
            if reader.transition(version, value + 1) != Err(Error::Rights)
                || writer.read() != Err(Error::Rights)
                || writer.transition(version, value + 1) != Ok(version + 1)
                || reader.read() != Ok((version + 1, value + 1))
            {
                return 88;
            }
            let _ = start
                .console
                .write_str("user-multi-handle: ordered narrowed copies verified\n");
            0
        }
        // Milestone 2 composition: the only cell authority is write-only,
        // and ordinary output is a write-only pipe installed as console.
        [cell, console] if *console == start.console.raw() => {
            let cell = Cell::from_raw(*cell);
            let mut forbidden_read = [0u8; 1];
            if cell.read() != Err(Error::Rights)
                || start.console.read_once(&mut forbidden_read) != Err(Error::Rights)
                || cell.transition(0, 101) != Ok(1)
            {
                return 87;
            }
            if start
                .console
                .write_str("pipe-cell: version 1 value 101\n")
                .is_err()
            {
                return 87;
            }
            0
        }
        _ => 88,
    }
}
