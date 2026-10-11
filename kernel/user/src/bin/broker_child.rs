//! The default image of init's brokered owner programs (docs/BROKER.md).
//! Its first argument chooses a behaviour: `echo` copies stdin to stdout
//! after reporting its argv and authority on stderr; `fault`, `exit N`,
//! `sleep N`; `nest` and `nest-hold` request a program themselves.
#![no_std]
#![no_main]

use absd_user::broker::{
    Channel, MAX_STARTUP_BYTES, REPLY_EXITED, REPLY_STARTED, ROLE_BLOCK, ROLE_STDERR, ROLE_STDIN,
    Startup, read_to_end,
};
use absd_user::{Block, Error, MultiStart, Pipe, program, sleep, spawn};

absd_user::multi_entry!(main);

static mut RECORD: [u8; MAX_STARTUP_BYTES] = [0; MAX_STARTUP_BYTES];

fn number(bytes: &[u8]) -> Option<u64> {
    core::str::from_utf8(bytes).ok()?.parse().ok()
}

fn main(start: MultiStart<'_>) -> i32 {
    let handles = start.handles;
    if handles.len() < 4 || handles[handles.len() - 1] != start.console.raw() {
        return 80;
    }
    let record = unsafe { &mut *core::ptr::addr_of_mut!(RECORD) };
    let Ok(length) = read_to_end(Pipe::from_raw(handles[0]), record) else {
        return 81;
    };
    let Some(startup) = Startup::parse(&record[..length], handles.len()) else {
        return 82;
    };
    let (Some(stdin), Some(stderr)) = (startup.role(ROLE_STDIN, 0), startup.role(ROLE_STDERR, 0))
    else {
        return 83;
    };
    let stdin = Pipe::from_raw(handles[stdin]);
    let stderr = Pipe::from_raw(handles[stderr]);
    let stdout = start.console;
    let mut args = startup.args();
    let mode = args.next().unwrap_or(b"");
    match mode {
        b"echo" => {
            let _ = stderr.write_all(b"argv=echo");
            for arg in startup.args().skip(1) {
                let _ = stderr.write_all(b" ");
                let _ = stderr.write_all(arg);
            }
            // The broker handed over no spawn right and at most a read-only
            // block handle; the kernel, not this program, refuses both.
            let spawn = match spawn(program::EXIT7) {
                Err(Error::Rights) => "refused",
                _ => "ALLOWED",
            };
            let block = match startup.role(ROLE_BLOCK, 0) {
                None => "absent",
                Some(index) => {
                    let block = Block::from_raw(handles[index]);
                    let mut sector = [0u8; absd_user::BLOCK_SECTOR_BYTES];
                    match (
                        block.read_sector(0, &mut sector),
                        block.write_sector(0, &sector),
                    ) {
                        (Ok(()), Err(Error::Rights)) => "read-only",
                        _ => "WRITABLE",
                    }
                }
            };
            let boot = absd_user::boot_id().map(|id| id[0] as u64 | (id[1] as u64) << 8);
            let _ = absd_user::cprintln!(
                absd_user::Console::from_raw(stderr.raw()),
                " spawn={spawn} block={block} handles={} boot={:?}",
                handles.len(),
                boot.ok()
            );
            let mut buffer = [0u8; 256];
            loop {
                match stdin.read_once(&mut buffer) {
                    Ok(0) => return 0,
                    Ok(count) => {
                        if stdout.write_all(&buffer[..count]).is_err() {
                            return 84;
                        }
                    }
                    Err(_) => return 85,
                }
            }
        }
        b"fault" => unsafe { core::arch::asm!("ud2", options(noreturn)) },
        b"exit" => args
            .next()
            .and_then(number)
            .map_or(86, |status| status as i32),
        b"sleep" => {
            sleep(args.next().and_then(number).unwrap_or(1));
            0
        }
        b"nest" | b"nest-hold" => {
            let Some(channel) = Channel::from_startup(handles, &startup) else {
                return 87;
            };
            if mode == b"nest-hold" {
                if channel
                    .send(0, b"/owners/sleep", &[b"sleep", b"1000000"])
                    .is_err()
                    || !matches!(channel.next_reply(), Ok((REPLY_STARTED, 0, _, _)))
                {
                    return 88;
                }
                let _ = absd_user::cprintln!(stdout, "NESTED HOLD started");
                sleep(1_000_000);
                return 0;
            }
            let (writer, reader, _) = channel.slots[0];
            if channel
                .send(0, b"/owners/echo", &[b"echo", b"nested"])
                .is_err()
            {
                return 89;
            }
            let Ok((REPLY_STARTED, 0, _, pid)) = channel.next_reply() else {
                return 90;
            };
            let writer = Pipe::from_raw(writer);
            if writer.write_all(b"deep").is_err() || absd_user::close(writer.raw()).is_err() {
                return 91;
            }
            let mut output = [0u8; 32];
            let Ok(count) = read_to_end(Pipe::from_raw(reader), &mut output) else {
                return 92;
            };
            let Ok((REPLY_EXITED, 0, _, status)) = channel.next_reply() else {
                return 93;
            };
            let echoed = core::str::from_utf8(&output[..count]).unwrap_or("?");
            let _ = absd_user::cprintln!(
                stdout,
                "NESTED echo={echoed} status={status} grandchild={}",
                pid > 0
            );
            0
        }
        _ => 94,
    }
}
