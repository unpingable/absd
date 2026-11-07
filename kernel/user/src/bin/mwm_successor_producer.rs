//! Configured producer: parent configures identity, count, pace and optional final crash.
#![no_std]
#![no_main]
#[allow(
    dead_code,
    reason = "Producer and consumer use complementary parts of this private wire protocol."
)]
#[path = "../mwm_successor.rs"]
mod transport;
use absd_user::{Error, MultiStart, Pipe, close, sleep, time};
use transport::*;
absd_user::multi_entry!(main);
static mut PAYLOAD: [u8; FRAME] = [0; FRAME];
fn word(reader: Pipe) -> Result<u64, Error> {
    let mut bytes = [0; 8];
    let mut used = 0;
    while used < bytes.len() {
        let n = reader.read_timeout(&mut bytes[used..], 30_000)?;
        if n == 0 {
            return Err(Error::Invalid);
        }
        used += n;
    }
    Ok(u64::from_le_bytes(bytes))
}
fn produce(writer: Pipe, control: Pipe) -> Result<(), Error> {
    let session = word(control)?;
    let generation = word(control)?;
    if session == 0 || generation == 0 {
        return Err(Error::Invalid);
    }
    let count = word(control)?;
    let delay = word(control)?;
    let crash = word(control)?;
    if count == 0 || count > 24 || delay > 1000 || crash > 1 {
        return Err(Error::Invalid);
    }
    for sequence in 1..=count {
        let payload = unsafe { &mut *core::ptr::addr_of_mut!(PAYLOAD) };
        for (i, pixel) in payload.iter_mut().enumerate() {
            *pixel = (session as u8)
                .wrapping_add(generation as u8)
                .wrapping_add((sequence as u8).wrapping_mul(31))
                .wrapping_add((i / WIDTH + i % WIDTH) as u8);
        }
        // Write-side BrokenPipe remains a failed producer, never EOF.
        writer.write_all(&header(session, generation, sequence, payload))?;
        for index in 1..CHUNKS {
            writer.write_all(&chunk(session, generation, sequence, index, payload))?;
        }
        writer.write_all(&trailer(session, generation, sequence, time()))?;
        sleep(delay);
    }
    if crash == 1 {
        // Truncated next frame plus a real process fault; no orderly completion.
        let payload = unsafe { &*core::ptr::addr_of!(PAYLOAD) };
        writer.write_all(&header(session, generation, count + 1, payload)[..127])?;
        unsafe {
            core::arch::asm!("ud2", options(noreturn));
        }
    }
    writer.write_all(&completion(session, generation, count))
}
fn main(start: MultiStart<'_>) -> i32 {
    let [writer, control, console] = start.handles else {
        return 90;
    };
    if *console != start.console.raw() {
        return 90;
    }
    let result = produce(Pipe::from_raw(*writer), Pipe::from_raw(*control));
    let closed = close(*writer).and(close(*control));
    if result.is_ok() && closed.is_ok() {
        0
    } else {
        let _ = start
            .console
            .write_str("MWM SLICE3 PRODUCER WRITE FAILED\n");
        91
    }
}
