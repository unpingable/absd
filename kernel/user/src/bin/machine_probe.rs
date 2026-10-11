//! Tries to end the machine through the handle init gave it. Init starts it
//! with `handle` either zero, a machine handle narrowed to the restart
//! right, or (the `machine-recover-test` boot) one narrowed to the recover
//! right, and `arg` set to the value of init's own machine handle, which
//! names nothing in this process. Recover comes first: a recover-only
//! handle resets the machine there, and that reset is the evidence. Every
//! other attempt must be refused; the exit status reports how the kernel
//! refused both recover and stop through `handle`: 1 no machine handle
//! (`BadHandle`), 2 no right (`Rights`).
#![no_std]
#![no_main]

use absd_user::{Error, Start, machine_recover, machine_restart, machine_stop};

absd_user::entry!(main);

fn main(start: Start) -> i32 {
    // Another process's handle value is not authority here.
    if machine_stop(start.arg, absd_user::STOP_CODE_MIN) != Error::BadHandle
        || machine_restart(start.arg) != Err(Error::BadHandle)
        || machine_recover(start.arg) != Error::BadHandle
        || start.machine != 0
    {
        return 8;
    }
    let recovered = machine_recover(start.handle);
    match (
        recovered,
        machine_stop(start.handle, absd_user::STOP_CODE_MIN),
    ) {
        (Error::BadHandle, Error::BadHandle) => 1,
        (Error::Rights, Error::Rights) => 2,
        _ => 9,
    }
}
