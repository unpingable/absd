//! Durable-boot composition probe. As the worker it exits cleanly (step 1)
//! or leaves a live orphan behind (step 2); as the reader (input `reader`)
//! it proves the block handle init gave it cannot write. The worker comes
//! with a startup record and a machine handle holding the stop right only;
//! the reader keeps the four-handle vector and gets no machine handle.
#![no_std]
#![no_main]

use absd_user::broker::{ROLE_BLOCK, ROLE_MACHINE, ROLE_STDIN, ROLE_STEP, Startup, read_to_end};
use absd_user::{
    Block, Cell, Error, MultiStart, Pipe, machine_restart, machine_stop, program, spawn_with,
};

absd_user::multi_entry!(main);

static mut RECORD: [u8; 512] = [0; 512];

/// `(input, block, step cell, machine)`: the four-handle vector, or the
/// roles of a startup record.
fn layout(handles: &[u64]) -> Option<(u64, u64, u64, u64)> {
    if let [input, block, cell, _console] = handles {
        return Some((*input, *block, *cell, 0));
    }
    let record = unsafe { &mut *core::ptr::addr_of_mut!(RECORD) };
    let length = read_to_end(Pipe::from_raw(*handles.first()?), record).ok()?;
    let startup = Startup::parse(&record[..length], handles.len())?;
    let at = |role| startup.role(role, 0).map(|index| handles[index]);
    Some((
        at(ROLE_STDIN)?,
        at(ROLE_BLOCK)?,
        at(ROLE_STEP)?,
        at(ROLE_MACHINE).unwrap_or(0),
    ))
}

fn main(start: MultiStart<'_>) -> i32 {
    let Some((input_handle, block_handle, cell_handle, machine)) = layout(start.handles) else {
        return 90;
    };
    if start.handles.last() != Some(&start.console.raw()) {
        return 90;
    }
    let input_raw = &input_handle;
    let block_raw = &block_handle;
    let cell_raw = &cell_handle;
    let mut input = [0u8; 16];
    let mut length = 0;
    loop {
        match Pipe::from_raw(*input_raw).read_once(&mut input[length..]) {
            Ok(0) => break,
            Ok(count) => length += count,
            Err(_) => return 91,
        }
        if length == input.len() {
            return 91;
        }
    }
    let block = Block::from_raw(*block_raw);
    if &input[..length] == b"reader" {
        let mut sector = [0u8; absd_user::BLOCK_SECTOR_BYTES];
        if block.read_sector(0, &mut sector).is_err() {
            return 92;
        }
        if block.write_sector(0, &sector) != Err(Error::Rights)
            || block.flush() != Err(Error::Rights)
        {
            return 93;
        }
        return match absd_user::cprintln!(
            start.console,
            "DURABLE PROBE READER write=refused flush=refused"
        ) {
            Ok(()) => 0,
            Err(_) => 94,
        };
    }
    let Ok((_, step)) = Cell::from_raw(*cell_raw).read() else {
        return 95;
    };
    // The worker's machine handle stops the machine and does nothing else:
    // the kernel refuses a restart through it, and a code outside the
    // range, without stopping anything.
    if machine_restart(machine) != Err(Error::Rights) || machine_stop(machine, 5) != Error::Invalid
    {
        return 97;
    }
    match step {
        1 => {}
        2 => {
            // A descendant that outlives this worker; it inherits no handle,
            // but init cannot know that, and must not go on while it lives.
            if spawn_with(program::SLEEPER, 0, 60_000).is_err() {
                return 96;
            }
        }
        _ => return 99,
    }
    match absd_user::cprintln!(
        start.console,
        "DURABLE PROBE WORKER step={step} machine=stop-only"
    ) {
        Ok(()) => 0,
        Err(_) => 98,
    }
}
