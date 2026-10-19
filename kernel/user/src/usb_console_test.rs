//! Explicit shell-role qualification through ordinary Console syscalls.
use absd_user::{Console, Error, RIGHT_WRITE, close, duplicate, sleep};

pub fn run(console: Console) -> i32 {
    let mut byte = [0];
    let _ = console.write_str("USB CONSOLE READY\n");
    if console.read_timeout(&mut byte, 5000) != Ok(1) || byte != *b"a" {
        return 71;
    }
    let _ = console.write_str("USB CONSOLE QUEUE READY\n");
    sleep(1000);
    let Ok(narrowed) = duplicate(console.raw(), RIGHT_WRITE) else {
        return 72;
    };
    let denied = Console::from_raw(narrowed).read_once(&mut byte);
    if close(narrowed).is_err() || denied != Err(Error::Rights) {
        return 73;
    }
    // 'b' was queued while this process slept. Refusal must not consume it.
    if console.read_timeout(&mut byte, 1000) != Ok(1) || byte != *b"b" {
        return 74;
    }
    let _ = console.write_str("USB CONSOLE RIGHTS OK\nUSB CONSOLE RACE ARMED\n");
    // The explicit kernel fixture holds the actual 'c' completion until this
    // deadline. wake_sleepers runs before the BSP keyboard pump.
    if console.read_timeout(&mut byte, 1000) != Err(Error::Timeout) {
        return 75;
    }
    if console.read_timeout(&mut byte, 1000) != Ok(1) || byte != *b"c" {
        return 76;
    }
    let _ = console.write_str("USB CONSOLE RACE OK\n");
    0
}
