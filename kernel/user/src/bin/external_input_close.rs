//! Qualification fixture: close stdin, write four pipe capacities, then exit.
#![no_std]
#![no_main]

use absd_user::broker::{MAX_STARTUP_BYTES, ROLE_STDIN, Startup, read_to_end};
use absd_user::{MultiStart, Pipe, close};

absd_user::multi_entry!(main);

fn main(start: MultiStart<'_>) -> i32 {
    let Some(&first) = start.handles.first() else {
        return 90;
    };
    let output_raw = start.console.raw();
    if start.handles.last() != Some(&output_raw) {
        return 90;
    }
    // These controls give plain workers two handles and durable readers
    // four (stdin, block, step, console). Durable workers instead receive
    // the existing versioned startup record and its explicitly named roles.
    let simple = matches!(start.handles.len(), 2 | 4);
    let mut output_aliases = [0u64; 2];
    let input_raw = if !simple {
        let mut record = [0u8; MAX_STARTUP_BYTES];
        let Ok(length) = read_to_end(Pipe::from_raw(first), &mut record) else {
            return 90;
        };
        let Some(startup) = Startup::parse(&record[..length], start.handles.len()) else {
            return 90;
        };
        let Some(index) = startup.role(ROLE_STDIN, 0) else {
            return 90;
        };
        if close(first).is_err() {
            return 90;
        }
        for (slot, role) in [
            absd_user::broker::ROLE_STDOUT,
            absd_user::broker::ROLE_STDERR,
        ]
        .into_iter()
        .enumerate()
        {
            if let Some(index) = startup.role(role, 0) {
                output_aliases[slot] = start.handles[index];
            }
        }
        start.handles[index]
    } else {
        first
    };
    let input = Pipe::from_raw(input_raw);
    let mut mode = [0u8; 1];
    if input.read_once(&mut mode) != Ok(1) {
        return 91;
    }
    if mode[0] != b'E' && close(input_raw).is_err() {
        return 91;
    }
    let mut output = [0u8; 4096];
    for (index, byte) in output.iter_mut().enumerate() {
        *byte = (index % 251) as u8;
    }
    if start.console.write_all(&output).is_err() {
        return 92;
    }
    if mode[0] == b'T' {
        loop {
            absd_user::sleep(100);
        }
    }
    if mode[0] == b'E' {
        let handles = [output_raw, output_aliases[0], output_aliases[1]];
        for (index, handle) in handles.into_iter().enumerate() {
            if handle != 0 && !handles[..index].contains(&handle) && close(handle).is_err() {
                return 93;
            }
        }
        // The supervisor must kill us before presenting EOF on a refused
        // incomplete input. Returning zero makes premature EOF observable.
        let mut bytes = [0u8; 128];
        loop {
            match input.read_once(&mut bytes) {
                Ok(0) => return 0,
                Ok(_) => {}
                Err(_) => return 94,
            }
        }
    }
    if mode[0] == b'0' { 0 } else { 96 }
}
