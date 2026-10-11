//! Consumes one exact bounded stream through a read-only pipe and reports a
//! compact result through a separately captured write-only console.
#![no_std]
#![no_main]

use absd_user::{Error, MultiStart, Pipe};

const FNV_OFFSET: u32 = 0x811c_9dc5;
const FNV_PRIME: u32 = 0x0100_0193;

absd_user::multi_entry!(main);

fn main(start: MultiStart<'_>) -> i32 {
    let [input_raw, console_raw] = start.handles else {
        return 90;
    };
    if *console_raw != start.console.raw() {
        return 90;
    }
    let input = Pipe::from_raw(*input_raw);
    if input.write_once(b"x") != Err(Error::Rights)
        || start.console.read_once(&mut [0u8; 1]) != Err(Error::Rights)
    {
        return 91;
    }

    let mut digest = FNV_OFFSET;
    let mut total = 0usize;
    loop {
        let mut bytes = [0u8; 193];
        let Ok(count) = input.read_once(&mut bytes) else {
            return 92;
        };
        if count == 0 {
            break;
        }
        total += count;
        if total > absd_abi::program::INPUT_STREAM_BYTES {
            return 93;
        }
        for &byte in &bytes[..count] {
            digest = (digest ^ byte as u32).wrapping_mul(FNV_PRIME);
        }
    }

    if total != absd_abi::program::INPUT_STREAM_BYTES
        || digest != absd_abi::program::INPUT_STREAM_DIGEST
    {
        return 94;
    }
    if absd_user::cprintln!(
        start.console,
        "stream-input: bytes={} digest={:08x}",
        total,
        digest
    )
    .is_err()
    {
        return 95;
    }
    0
}
