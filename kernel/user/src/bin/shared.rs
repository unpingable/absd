//! One of several children racing on a cell handed over by the parent. Each
//! transition names the version this process last read, so a change by a
//! sibling in between is refused and simply retried; nothing is lost.
#![no_std]
#![no_main]

use absd_user::{Cell, Error, Start, yield_now};

absd_user::entry!(main);

const TRANSITIONS: u64 = 50;

fn main(start: Start) -> i32 {
    let console = start.console;
    if start.handle == 0 || start.arg == 0 {
        let _ = console.write_str("user-shared: no cell or id handed over\n");
        return 90;
    }
    let cell = Cell::from_raw(start.handle);
    let mut done = 0;
    while done < TRANSITIONS {
        let Ok((version, value)) = cell.read() else {
            return 90;
        };
        match cell.transition(version, value + 1) {
            Ok(_) => done += 1,
            // A sibling moved the cell first: read again and retry.
            Err(Error::Stale) => {}
            Err(_) => return 90,
        }
        if done % 8 == 0 {
            yield_now();
        }
    }
    // One write, so another process's output cannot split the line.
    let mut line = *b"user-shared: racer ? done\n";
    line[19] = b'0' + start.arg as u8;
    let _ = console.write_once(&line);
    0
}
