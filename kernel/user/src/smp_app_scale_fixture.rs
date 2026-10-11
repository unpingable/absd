//! Six-worker supervisor fixture for the closed SMP application-scale test.
//!
//! The controller distributes six supervisors across the selected CPU count.
//! Each supervisor streams the same sealed text corpus through a private pipe
//! to the catalogued real text-stats executable, then verifies the exact
//! output before publishing its completion word.

use super::*;
use absd_user::{
    Error, Outcome, Pipe, RIGHT_READ, RIGHT_WRITE, SpawnHandleCopy, close, duplicate, info,
    program, spawn_many_copy, wait_timeout,
};

const WORKERS: usize = 6;
const FIRST_ROLE: u64 = 350;
const INPUT_LINE: &[u8] = b"alpha beta alpha gamma beta alpha\n";
const INPUT_REPETITIONS: usize = 32768;
const INPUT_BYTES: usize = INPUT_LINE.len() * INPUT_REPETITIONS;
const TRANSFER_TIMEOUT_TICKS: u64 = 64;
const FIXTURE_DEADLINE_TSC: u64 = 1 << 38;
const EXPECTED_OUTPUT: &[u8] = b"bytes=1114112 lines=32768 words=196608 unique=3\nalpha=98304\nbeta=65536\ngamma=32768\nABSD RUST TEXT STATS OK\n";

fn fixture_require(ok: bool, message: &'static str) -> Result<(), &'static str> {
    if ok { Ok(()) } else { Err(message) }
}

fn fixture_deadline(begin: u64, message: &'static str) -> Result<(), &'static str> {
    fixture_require(
        deadline().wrapping_sub(begin) < FIXTURE_DEADLINE_TSC,
        message,
    )
}

fn pipe_ends() -> Result<(Pipe, Pipe), &'static str> {
    let full = Pipe::create().map_err(|_| "app-scale pipe create")?;
    let reader = duplicate(full.raw(), RIGHT_READ).map_err(|_| "app-scale pipe reader")?;
    let writer = match duplicate(full.raw(), RIGHT_WRITE) {
        Ok(handle) => handle,
        Err(_) => {
            let _ = close(reader);
            let _ = close(full.raw());
            return Err("app-scale pipe writer");
        }
    };
    close(full.raw()).map_err(|_| "app-scale pipe base close")?;
    Ok((Pipe::from_raw(reader), Pipe::from_raw(writer)))
}

fn publish_failure(index: usize, result: Result<(), &'static str>) -> Result<(), &'static str> {
    if result.is_err() {
        store(248 + index, 2);
    }
    result
}

fn controller() -> Result<(), &'static str> {
    for index in 240..254 {
        store(index, 0);
    }

    let mut children: [Option<Child>; WORKERS] = [None; WORKERS];
    for (index, child) in children.iter_mut().enumerate() {
        *child = Some(spawn(FIRST_ROLE + index as u64, 0)?);
    }

    let begin = deadline();
    for index in 0..WORKERS {
        while load(240 + index) != 1 {
            fixture_deadline(begin, "app-scale supervisor readiness timeout")?;
            fixture_require(
                load(248 + index) != 2,
                "app-scale supervisor failed before ready",
            )?;
            yield_now();
        }
    }

    loop {
        fixture_deadline(begin, "app-scale start barrier timeout")?;
        match test(44, 0, 0) {
            1 => break,
            0 => yield_now(),
            _ => return Err("app-scale start barrier rejected"),
        }
    }
    store(246, 1);

    for child in children.into_iter().flatten() {
        loop {
            fixture_deadline(begin, "app-scale supervisor wait timeout")?;
            let outcome = wait_timeout(Some(child), TRANSFER_TIMEOUT_TICKS);
            fixture_deadline(begin, "app-scale supervisor wait timeout")?;
            match outcome {
                Ok(Outcome::Exited(0)) => break,
                Ok(_) => return Err("app-scale supervisor exit"),
                Err(Error::Timeout) => {}
                Err(_) => return Err("app-scale supervisor wait"),
            }
        }
    }
    for index in 0..WORKERS {
        fixture_require(load(248 + index) == 1, "app-scale supervisor completion")?;
    }
    fixture_require(test(45, 0, 0) == 0, "app-scale completion receipt")
}

fn fnv32_update(mut hash: u32, bytes: &[u8]) -> u32 {
    for &byte in bytes {
        hash ^= u32::from(byte);
        hash = hash.wrapping_mul(16_777_619);
    }
    hash
}

fn feed_input(writer: Pipe, begin: u64) -> Result<u32, &'static str> {
    let mut offset = 0usize;
    let mut hash = 0x811c_9dc5u32;
    let mut chunk = [0u8; absd_user::MAX_WRITE];

    while offset < INPUT_BYTES {
        fixture_deadline(begin, "app-scale input deadline")?;
        let length = (INPUT_BYTES - offset).min(chunk.len());
        for (index, byte) in chunk[..length].iter_mut().enumerate() {
            *byte = INPUT_LINE[(offset + index) % INPUT_LINE.len()];
        }
        match writer.write_timeout(&chunk[..length], TRANSFER_TIMEOUT_TICKS) {
            Ok(0) => return Err("app-scale zero input write"),
            Ok(written) => {
                hash = fnv32_update(hash, &chunk[..written]);
                offset += written;
            }
            Err(Error::Timeout) => {}
            Err(_) => return Err("app-scale input write"),
        }
    }
    close(writer.raw()).map_err(|_| "app-scale input writer close")?;
    Ok(hash)
}

fn drain_output(reader: Pipe, begin: u64) -> Result<([u8; 256], usize), &'static str> {
    let mut output = [0u8; 256];
    let mut length = 0usize;
    let mut chunk = [0u8; absd_user::MAX_WRITE];
    loop {
        fixture_deadline(begin, "app-scale output deadline")?;
        match reader.read_timeout(&mut chunk, TRANSFER_TIMEOUT_TICKS) {
            Ok(0) => break,
            Ok(count) => {
                fixture_require(length + count <= output.len(), "app-scale output overflow")?;
                output[length..length + count].copy_from_slice(&chunk[..count]);
                length += count;
            }
            Err(Error::Timeout) => {}
            Err(_) => return Err("app-scale output read"),
        }
    }
    Ok((output, length))
}

fn supervisor(role: u64) -> Result<(), &'static str> {
    let index = (role - FIRST_ROLE) as usize;
    fixture_require(index < WORKERS, "app-scale supervisor role")?;
    let result = supervisor_inner(index);
    publish_failure(index, result)
}

fn supervisor_inner(index: usize) -> Result<(), &'static str> {
    let begin = deadline();
    let (input_reader, input_writer) = pipe_ends()?;
    let (output_reader, output_writer) = pipe_ends()?;
    let copies = [
        SpawnHandleCopy::new(input_reader.raw(), RIGHT_READ),
        SpawnHandleCopy::console(output_writer.raw(), RIGHT_WRITE),
    ];
    let child = spawn_many_copy(program::EXTERNAL_WORKLOAD, &copies)
        .map_err(|_| "app-scale native text-stats spawn")?;
    let child_pid = info(Some(child))
        .map_err(|_| "app-scale native text-stats identity")?
        .pid;

    fixture_require(
        test(43, child_pid, input_reader.raw()) == 0,
        "app-scale native input registration",
    )?;
    close(input_reader.raw()).map_err(|_| "app-scale parent input reader close")?;
    close(output_writer.raw()).map_err(|_| "app-scale parent output writer close")?;

    store(240 + index, 1);
    while load(246) != 1 {
        fixture_deadline(begin, "app-scale release barrier timeout")?;
        yield_now();
    }

    let input_hash = feed_input(input_writer, begin)?;
    let (output, output_length) = drain_output(output_reader, begin)?;
    loop {
        fixture_deadline(begin, "app-scale native wait timeout")?;
        let outcome = wait_timeout(Some(child), TRANSFER_TIMEOUT_TICKS);
        fixture_deadline(begin, "app-scale native wait timeout")?;
        match outcome {
            Ok(Outcome::Exited(0)) => break,
            Ok(_) => return Err("app-scale native text-stats exit"),
            Err(Error::Timeout) => {}
            Err(_) => return Err("app-scale native text-stats wait"),
        }
    }
    close(output_reader.raw()).map_err(|_| "app-scale parent output reader close")?;

    fixture_require(
        test(46, INPUT_BYTES as u64, u64::from(input_hash)) == 0,
        "app-scale input receipt",
    )?;
    fixture_require(
        test(47, output.as_ptr() as u64, output_length as u64) == 0,
        "app-scale output receipt",
    )?;
    fixture_require(
        &output[..output_length] == EXPECTED_OUTPUT,
        "app-scale exact text-stats output",
    )?;
    store(248 + index, 1);
    Ok(())
}

pub fn run(start: Start) -> Result<(), &'static str> {
    match start.arg {
        0 => controller(),
        role @ FIRST_ROLE..=355 => supervisor(role),
        _ => Err("app-scale role"),
    }
}
