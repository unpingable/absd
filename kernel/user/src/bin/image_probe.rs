//! `spawn_image` (syscall 31): a child from a static ELF64 image held in this
//! process's own memory, and the refusals around it. The images are built
//! here, byte by byte, so every negative control mutates exactly one field
//! of a known-good image. Run as the external workload
//! (`scripts/spawn-image-test.sh`); the kernel's accounting line afterwards
//! proves every refusal and every child left nothing behind.
#![no_std]
#![no_main]

use absd_user::{
    Child, Error, MAX_SPAWN_IMAGE_BYTES, MultiStart, Outcome, Pipe, RIGHT_READ, RIGHT_WRITE,
    SPAWN_NO_SPAWN, SpawnHandleCopy, close, duplicate, info, spawn_image, spawn_image_raw, wait,
};
use core::fmt::Write as _;

absd_user::multi_entry!(main);

const BASE: u64 = absd_abi::layout::USER_IMAGE_MIN;
const CODE: usize = 120;
const MESSAGE: &[u8] = b"image child ok\n";

/// Writes `MESSAGE` to the console it starts with (RDI), then exits 42.
fn writer_code(message_address: u64) -> [u8; 36] {
    let mut code = [0u8; 36];
    code[0..2].copy_from_slice(&[0x48, 0xbe]); // mov rsi, imm64
    code[2..10].copy_from_slice(&message_address.to_le_bytes());
    code[10] = 0xba; // mov edx, imm32
    code[11..15].copy_from_slice(&(MESSAGE.len() as u32).to_le_bytes());
    code[15..20].copy_from_slice(&[0xb8, 1, 0, 0, 0]); // mov eax, SYS_WRITE
    code[20..22].copy_from_slice(&[0xcd, 0x80]);
    code[22..27].copy_from_slice(&[0xbf, 42, 0, 0, 0]); // mov edi, 42
    code[27..32].copy_from_slice(&[0xb8, 3, 0, 0, 0]); // mov eax, SYS_EXIT
    code[32..34].copy_from_slice(&[0xcd, 0x80]);
    code[34..36].copy_from_slice(&[0x0f, 0x0b]);
    code
}

/// Calls `spawn_image(0, 0, 0)` and exits with its result: `-1` without the
/// spawn right, `-14` (the null request) with it.
const SPAWNER_CODE: [u8; 24] = [
    0xb8, 31, 0, 0, 0, // mov eax, SYS_SPAWN_IMAGE
    0x31, 0xff, // xor edi, edi
    0x31, 0xf6, // xor esi, esi
    0x31, 0xd2, // xor edx, edx
    0xcd, 0x80, // int 0x80
    0x89, 0xc7, // mov edi, eax
    0xb8, 3, 0, 0, 0, // mov eax, SYS_EXIT
    0xcd, 0x80, // int 0x80
    0x0f, 0x0b, // ud2
];

struct Image {
    bytes: [u8; 256],
    length: usize,
}

impl Image {
    /// ELF64 header, one R+X `PT_LOAD` covering the whole file at `BASE`,
    /// the code at offset 120 (the entry point), and `data` after it.
    fn new(code: &[u8], data: &[u8]) -> Self {
        let mut bytes = [0u8; 256];
        let length = CODE + code.len() + data.len();
        bytes[0..8].copy_from_slice(&[0x7f, b'E', b'L', b'F', 2, 1, 1, 0]);
        put16(&mut bytes, 16, 2); // ET_EXEC
        put16(&mut bytes, 18, 62); // x86-64
        put32(&mut bytes, 20, 1);
        put64(&mut bytes, 24, BASE + CODE as u64);
        put64(&mut bytes, 32, 64);
        put16(&mut bytes, 52, 64);
        put16(&mut bytes, 54, 56);
        put16(&mut bytes, 56, 1);
        put32(&mut bytes, 64, 1); // PT_LOAD
        put32(&mut bytes, 68, 5); // R + X
        put64(&mut bytes, 72, 0);
        put64(&mut bytes, 80, BASE);
        put64(&mut bytes, 88, BASE);
        put64(&mut bytes, 96, length as u64);
        put64(&mut bytes, 104, length as u64);
        put64(&mut bytes, 112, 0x1000);
        bytes[CODE..CODE + code.len()].copy_from_slice(code);
        bytes[CODE + code.len()..length].copy_from_slice(data);
        Self { bytes, length }
    }
    fn writer() -> Self {
        let message = BASE + CODE as u64 + 36;
        Self::new(&writer_code(message), MESSAGE)
    }
    fn as_slice(&self) -> &[u8] {
        &self.bytes[..self.length]
    }
    /// Moves the segment (and the entry point with it) to `address`.
    fn relocate(&mut self, address: u64) {
        put64(&mut self.bytes, 24, address + CODE as u64);
        put64(&mut self.bytes, 80, address);
        put64(&mut self.bytes, 88, address);
    }
}

fn put16(bytes: &mut [u8], at: usize, value: u16) {
    bytes[at..at + 2].copy_from_slice(&value.to_le_bytes());
}
fn put32(bytes: &mut [u8], at: usize, value: u32) {
    bytes[at..at + 4].copy_from_slice(&value.to_le_bytes());
}
fn put64(bytes: &mut [u8], at: usize, value: u64) {
    bytes[at..at + 8].copy_from_slice(&value.to_le_bytes());
}

fn code(result: Result<Child, Error>) -> i64 {
    match result {
        Ok(child) => {
            // A refusal was expected; do not leave the child behind.
            let _ = wait(Some(child));
            0
        }
        Err(Error::NotExecutable) => -8,
        Err(Error::Invalid) => -22,
        Err(Error::Fault) => -14,
        Err(Error::Rights) => -1,
        Err(Error::BadHandle) => -9,
        Err(Error::TooManyHandles) => -24,
        Err(_) => -9999,
    }
}

fn status(outcome: Result<Outcome, Error>) -> i64 {
    match outcome {
        Ok(Outcome::Exited(status)) => status as i64,
        _ => -9999,
    }
}

fn main(start: MultiStart<'_>) -> i32 {
    match run(&start) {
        Ok(()) => 0,
        Err(step) => {
            let mut console = start.console;
            let _ = writeln!(console, "SPAWN IMAGE FAILED at {step}");
            1
        }
    }
}

fn run(start: &MultiStart<'_>) -> Result<(), &'static str> {
    let mut console = start.console;
    let pipe = Pipe::create().map_err(|_| "pipe")?;
    let reader = Pipe::from_raw(duplicate(pipe.raw(), RIGHT_READ).map_err(|_| "reader")?);
    let writer = duplicate(pipe.raw(), RIGHT_WRITE).map_err(|_| "writer")?;
    close(pipe.raw()).map_err(|_| "pipe split")?;

    // The positive case: the child's only handle is the pipe as its console.
    let writer_image = Image::writer();
    let copies = [SpawnHandleCopy::console(writer, RIGHT_WRITE)];
    let child = spawn_image(writer_image.as_slice(), &copies, 0).map_err(|_| "spawn")?;
    let child_info = info(Some(child)).map_err(|_| "info")?;
    close(writer).map_err(|_| "writer close")?;
    let mut output = [0u8; 64];
    let mut length = 0;
    loop {
        let count = reader
            .read_once(&mut output[length..])
            .map_err(|_| "read")?;
        if count == 0 {
            break;
        }
        length += count;
    }
    close(reader.raw()).map_err(|_| "reader close")?;
    let first = status(wait(Some(child)));
    if &output[..length] != MESSAGE || first != 42 {
        return Err("child output");
    }
    let _ = writeln!(
        console,
        "SPAWN IMAGE child output=image child ok status={first} program={}",
        child_info.program
    );

    // Refusals of the image itself.
    let good = writer_image.as_slice();
    let mut malformed = Image::writer();
    malformed.bytes[1] = b'X';
    let truncated = &good[..good.len() - 1];
    let mut entry = Image::writer();
    put64(&mut entry.bytes, 24, BASE + 0x2000);
    let mut below = Image::writer();
    below.relocate(BASE - 0x1000);
    let mut above = Image::writer();
    above.relocate(absd_abi::layout::USER_IMAGE_MAX);
    let mut interp = Image::writer();
    put32(&mut interp.bytes, 64, 3); // PT_INTERP
    let _ = writeln!(
        console,
        "SPAWN IMAGE malformed={} truncated={} entry={} below-window={} above-window={} interp={}",
        code(spawn_image(malformed.as_slice(), &[], 0)),
        code(spawn_image(truncated, &[], 0)),
        code(spawn_image(entry.as_slice(), &[], 0)),
        code(spawn_image(below.as_slice(), &[], 0)),
        code(spawn_image(above.as_slice(), &[], 0)),
        code(spawn_image(interp.as_slice(), &[], 0)),
    );

    // Refusals of the request.
    let request = |image: u64, image_bytes: u64, handles: u64, handle_count: u64| {
        absd_abi::syscall::SpawnImageRequest {
            image,
            image_bytes,
            handles,
            handle_count,
        }
    };
    let raw = |request: &absd_abi::syscall::SpawnImageRequest, flags: u64, reserved: u64| {
        code(spawn_image_raw(request as *const _ as u64, flags, reserved))
    };
    let image = good.as_ptr() as u64;
    let length = good.len() as u64;
    let _ = writeln!(
        console,
        "SPAWN IMAGE zero={} oversize={} flags={} reserved={} count={}",
        raw(&request(image, 0, 0, 0), 0, 0),
        raw(&request(image, MAX_SPAWN_IMAGE_BYTES + 1, 0, 0), 0, 0),
        raw(&request(image, length, 0, 0), 1 << 32, 0),
        raw(&request(image, length, 0, 0), 0, 1),
        raw(&request(image, length, 0, 65), 0, 0),
    );
    let _ = writeln!(
        console,
        "SPAWN IMAGE fault request={} image={} handles={}",
        code(spawn_image_raw(0x1000, 0, 0)),
        raw(&request(0x1000, 4096, 0, 0), 0, 0),
        raw(&request(image, length, 0x1000, 1), 0, 0),
    );
    let not_process = [SpawnHandleCopy::new(0x7fff_ff00, RIGHT_READ)];
    let _ = writeln!(
        console,
        "SPAWN IMAGE handles stale={}",
        code(spawn_image(good, &not_process, 0)),
    );

    // The spawn right: a child started with SPAWN_NO_SPAWN is refused before
    // its (null) request is even read; the same image without the flag gets
    // as far as the pointer.
    let spawner = Image::new(&SPAWNER_CODE, &[]);
    let refused = spawn_image(spawner.as_slice(), &[], SPAWN_NO_SPAWN).map_err(|_| "no-spawn")?;
    let refused_pid = info(Some(refused)).map_err(|_| "no-spawn info")?.pid;
    let refused_status = status(wait(Some(refused)));
    let control = spawn_image(spawner.as_slice(), &[], 0).map_err(|_| "control")?;
    let control_pid = info(Some(control)).map_err(|_| "control info")?.pid;
    let control_status = status(wait(Some(control)));
    let _ = writeln!(
        console,
        "SPAWN IMAGE spawn-right child={refused_status} control={control_status}"
    );

    // No refusal consumed a PID: the children are numbered consecutively.
    let contiguous = refused_pid == child_info.pid + 1 && control_pid == refused_pid + 1;
    if refused_status != -1 || control_status != -14 || !contiguous {
        return Err("spawn right");
    }
    let _ = writeln!(console, "SPAWN IMAGE pids-contiguous={contiguous}");
    let _ = writeln!(console, "SPAWN IMAGE OK");
    Ok(())
}
