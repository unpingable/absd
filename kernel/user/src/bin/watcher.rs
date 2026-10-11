//! Blocks on a cell handed over by the parent and reports each change it
//! observes until the value reaches the stop mark. Wake-ups may coalesce
//! several transitions, so versions must only ever increase.
#![no_std]
#![no_main]

use absd_user::{Cell, Start};

absd_user::entry!(main);

const STOP: u64 = 100;

fn main(start: Start) -> i32 {
    let console = start.console;
    let cell = Cell::from_raw(start.handle);
    let mut seen = 0;
    let mut wakeups = 0u64;
    loop {
        let Ok(version) = cell.wait_change(seen) else {
            return 88;
        };
        if version <= seen {
            return 88;
        }
        seen = version;
        wakeups += 1;
        let Ok((now, value)) = cell.read() else {
            return 88;
        };
        if now < version {
            return 88;
        }
        if value >= STOP {
            break;
        }
    }
    if seen > STOP || wakeups == 0 || wakeups > STOP {
        return 88;
    }
    let _ = console.write_str("user-watcher: observed the cell reach its stop mark\n");
    0
}
