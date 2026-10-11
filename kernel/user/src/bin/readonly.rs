//! Receives a read-only duplicate of a cell: reading works, a transition
//! is refused for lack of the write right, and the parent's cell is
//! unchanged.
#![no_std]
#![no_main]

use absd_user::{Cell, Error, RIGHT_READ, RIGHT_WRITE, Start, duplicate};

absd_user::entry!(main);

fn main(start: Start) -> i32 {
    let console = start.console;
    let cell = Cell::from_raw(start.handle);
    let Ok((version, value)) = cell.read() else {
        return 89;
    };
    if cell.transition(version, value + 1) != Err(Error::Rights) {
        return 89;
    }
    // Rights only narrow: a read-only handle cannot mint a writable one,
    // but can duplicate itself.
    if duplicate(cell.raw(), RIGHT_READ | RIGHT_WRITE) != Err(Error::Rights) {
        return 89;
    }
    let Ok(again) = duplicate(cell.raw(), RIGHT_READ) else {
        return 89;
    };
    if Cell::from_raw(again).read() != Ok((version, value)) {
        return 89;
    }
    let _ = console.write_str("user-readonly: write right correctly withheld\n");
    0
}
