//! Private two-generation copied-frame presentation fixture.
#![no_std]
#![no_main]

use core::fmt::Write;

use absd_user::{
    Console, Error, LineBuffer, MultiStart, Pipe, RIGHT_READ, close, duplicate, sleep, syscall3,
};

use absd_user::mwm_protocol as protocol;

absd_user::multi_entry!(main);

const INFO: u64 = 0x7fd1;
const PRESENT: u64 = 0x7fd2;
const MASK: u64 = 0x7fd3;
const CONSOLE_RESTORE: u64 = 0x7fd4;
const FAULT: u64 = 0x7fdf;
const ACK_TICKS: u64 = 30_000;

fn main(start: MultiStart<'_>) -> i32 {
    let [display, ready, console] = start.handles else {
        return 90;
    };
    if *console != start.console.raw() {
        return 90;
    }
    match run(*display, Pipe::from_raw(*ready), start.console) {
        Ok(()) => 0,
        Err(step) => {
            let _ = start.console.write_str("MWM FAILED ");
            let _ = start.console.write_str(step);
            let _ = start.console.write_str("\n");
            91
        }
    }
}

fn run(display: u64, ready: Pipe, console: Console) -> Result<(), &'static str> {
    let info = info(display)?;
    let mut line = LineBuffer::new();
    let _ = writeln!(
        line,
        "MWM DISPLAY INFO generation={} high_water={} width=1024 height=768 pitch=4096 bpp=32 rgb=16:8,8:8,0:8",
        info.generation, info.high_water
    );
    console
        .write_all(line.as_bytes())
        .map_err(|_| "display information marker")?;
    match info.generation {
        1 => first(display, ready, console),
        2 if info.high_water == 0 => successor(display, console),
        _ => Err("generation or successor high-water"),
    }
}

fn info(display: u64) -> Result<protocol::DisplayInfo, &'static str> {
    let mut record = [0u8; 48];
    status(unsafe { syscall3(INFO, display, record.as_mut_ptr() as u64, 0) })?;
    protocol::parse_info(&record)
}

fn request(sequence: u64, x: u32, y: u32, generation: u64) -> [u8; 48] {
    let mut request = [0u8; 48];
    request[0..8].copy_from_slice(&sequence.to_le_bytes());
    request[8..12].copy_from_slice(&x.to_le_bytes());
    request[12..16].copy_from_slice(&y.to_le_bytes());
    request[16..20].copy_from_slice(&64u32.to_le_bytes());
    request[20..24].copy_from_slice(&64u32.to_le_bytes());
    request[24..28].copy_from_slice(&256u32.to_le_bytes());
    request[28..32].copy_from_slice(&(1u32 | (32 << 8)).to_le_bytes());
    request[32..40].copy_from_slice(&16_384u64.to_le_bytes());
    request[40..48].copy_from_slice(&generation.to_le_bytes());
    request
}

fn show(
    display: u64,
    sequence: u64,
    x: u32,
    y: u32,
    generation: u64,
    color: u32,
) -> Result<(), &'static str> {
    let pixels = protocol::rectangle(color);
    let request = request(sequence, x, y, generation);
    status(unsafe {
        syscall3(
            PRESENT,
            display,
            request.as_ptr() as u64,
            pixels.as_ptr() as u64,
        )
    })
}

fn mask(display: u64, sequence: u64, generation: u64) -> Result<(), &'static str> {
    status(unsafe { syscall3(MASK, display, sequence, generation) })
}

fn status(raw: i64) -> Result<(), &'static str> {
    if raw == 0 {
        Ok(())
    } else {
        Err("display call")
    }
}

fn refusal(console: Console, name: &str, raw: i64, expected: Error) -> Result<(), &'static str> {
    if Error::from_code(raw) != expected {
        return Err("negative display control");
    }
    let mut line = LineBuffer::new();
    let _ = writeln!(line, "MWM {name} REFUSED error={raw}");
    console
        .write_all(line.as_bytes())
        .map_err(|_| "refusal output")
}

fn first(display: u64, ready: Pipe, console: Console) -> Result<(), &'static str> {
    show(display, 1, 16, 16, 1, 0x20c080)?;
    console
        .write_str("MWM RECTANGLE READY\n")
        .map_err(|_| "rectangle marker")?;
    protocol::wait_ack(console, ACK_TICKS)?;

    let observer = duplicate(display, RIGHT_READ).map_err(|_| "read-only duplicate")?;
    let pixels = protocol::rectangle(0xc04040);
    let update = request(2, 32, 16, 1);
    let read_only = unsafe {
        syscall3(
            PRESENT,
            observer,
            update.as_ptr() as u64,
            pixels.as_ptr() as u64,
        )
    };
    close(observer).map_err(|_| "read-only close")?;
    refusal(console, "READ ONLY", read_only, Error::Rights)?;

    let malformed = unsafe {
        syscall3(
            PRESENT,
            display,
            request(2, 1000, 16, 1).as_ptr() as u64,
            pixels.as_ptr() as u64,
        )
    };
    refusal(console, "MALFORMED", malformed, Error::Invalid)?;

    mask(display, 2, 1)?;
    show(display, 3, 32, 16, 1, 0x20c080)?;
    console
        .write_str("MWM ANIMATION READY\n")
        .map_err(|_| "animation marker")?;
    protocol::wait_ack(console, ACK_TICKS)?;
    ready.write_all(b"MWM READY\n").map_err(|_| "readiness")?;
    sleep(3_600_000);
    Ok(())
}

fn successor(display: u64, console: Console) -> Result<(), &'static str> {
    show(display, 1, 32, 32, 2, 0xc04040)?;
    console
        .write_str("MWM SUCCESSOR READY\n")
        .map_err(|_| "successor marker")?;
    protocol::wait_ack(console, ACK_TICKS)?;
    console
        .write_str("MWM FAULT ACTIVE\n")
        .map_err(|_| "fault marker")?;
    let fault = unsafe { syscall3(FAULT, display, 2, 0) };
    refusal(console, "FAULT NOT ARMED", fault, Error::Invalid)?;
    status(unsafe { syscall3(CONSOLE_RESTORE, display, 2, 2) })
}
