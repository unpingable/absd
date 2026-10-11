//! Durable worker that exercises init's broker (docs/BROKER.md). The step
//! word picks the scenario: 1 the permitted, refused, failing, and nested
//! paths; 2 the requester ends while its child runs; 3 the same with a
//! nested requester holding a grandchild; 4 a malformed request; 5 the
//! requester ends right after asking; 6 it ends halfway through a request;
//! 7 it fails init's collection while its child runs; 8 it stops reading
//! replies; 9 it leaves init almost no pipes for a nested requester.
#![no_std]
#![no_main]

use absd_user::broker::{
    Channel, MAX_STARTUP_BYTES, REFUSED_NOT_PERMITTED, REFUSED_RESOURCES, REFUSED_SLOT,
    REPLY_EXITED, REPLY_REFUSED, REPLY_STARTED, ROLE_STEP, Startup, read_to_end,
};
use absd_user::{Cell, Console, Error, MultiStart, Pipe, program, sleep, spawn};

absd_user::multi_entry!(main);

static mut RECORD: [u8; MAX_STARTUP_BYTES] = [0; MAX_STARTUP_BYTES];

fn main(start: MultiStart<'_>) -> i32 {
    let handles = start.handles;
    let console = start.console;
    let record = unsafe { &mut *core::ptr::addr_of_mut!(RECORD) };
    let Ok(length) = read_to_end(Pipe::from_raw(handles[0]), record) else {
        return 70;
    };
    let Some(startup) = Startup::parse(&record[..length], handles.len()) else {
        return 71;
    };
    let Some(channel) = Channel::from_startup(handles, &startup) else {
        return 72;
    };
    let Some(step) = startup
        .role(ROLE_STEP, 0)
        .and_then(|index| Cell::from_raw(handles[index]).read().ok())
        .map(|(_, value)| value % 1_000_000_000_000)
    else {
        return 73;
    };
    match step {
        1 => match matrix(console, &channel) {
            Ok(()) => 0,
            Err(step) => {
                let _ = absd_user::cprintln!(console, "BROKER PROBE FAILED at {step}");
                74
            }
        },
        2 => {
            if channel
                .send(0, b"/owners/sleep", &[b"sleep", b"1000000"])
                .is_err()
                || !matches!(channel.next_reply(), Ok((REPLY_STARTED, 0, _, _)))
            {
                return 75;
            }
            let _ = absd_user::cprintln!(console, "BROKER PROBE leaving a running child");
            0
        }
        3 => {
            if channel
                .send(0, b"/owners/nest-hold", &[b"nest-hold"])
                .is_err()
                || !matches!(channel.next_reply(), Ok((REPLY_STARTED, 0, _, _)))
            {
                return 76;
            }
            let (_, stdout, _) = channel.slots[0];
            let mut line = [0u8; 32];
            let mut length = 0;
            while !line[..length].ends_with(b"\n") && length < line.len() {
                match Pipe::from_raw(stdout).read_once(&mut line[length..]) {
                    Ok(0) | Err(_) => return 77,
                    Ok(count) => length += count,
                }
            }
            let _ = absd_user::cprintln!(console, "BROKER PROBE leaving a nested requester");
            0
        }
        4 => {
            if channel.request.write_all(b"ABSDBR01\x09garbage").is_err() {
                return 78;
            }
            let refused = matches!(channel.next_reply(), Ok((REPLY_REFUSED, 0xff, 3, _)));
            // The channel is closed to further requests: a valid one now
            // gets no reply at all.
            let _ = channel.send(0, b"/owners/exit", &[b"exit", b"0"]);
            let silent = matches!(
                channel.reply.read_timeout(&mut [0u8; 24], 200),
                Err(Error::Timeout)
            );
            let _ = absd_user::cprintln!(
                console,
                "BROKER PROBE malformed refused={refused} then-silent={silent}"
            );
            if refused && silent { 0 } else { 79 }
        }
        5 => {
            let _ = channel.send(0, b"/owners/sleep", &[b"sleep", b"1000000"]);
            0
        }
        6 => {
            // Half a request, then gone: init must start nothing.
            let _ = channel.request.write_all(b"ABSDBR01\x01\x00");
            0
        }
        7 => {
            // A running child, then the worker fails init's collection: it
            // closes its console and outlives init's wait. The child must
            // still be reclaimed.
            if channel
                .send(0, b"/owners/sleep", &[b"sleep", b"1000000"])
                .is_err()
                || !matches!(channel.next_reply(), Ok((REPLY_STARTED, 0, _, _)))
            {
                return 80;
            }
            let _ = absd_user::cprintln!(console, "BROKER PROBE abandoning init's wait");
            let _ = absd_user::close(console.raw());
            sleep(1_000_000);
            0
        }
        8 => reply_flood(console, &channel),
        9 => pipe_pressure(console, &channel),
        _ => 99,
    }
}

fn expect(
    channel: &Channel,
    kind: u8,
    slot: u8,
    code: u32,
    step: &'static str,
) -> Result<i64, &'static str> {
    match channel.next_reply() {
        Ok((found, found_slot, found_code, value))
            if found == kind && found_slot == slot && found_code == code =>
        {
            Ok(value)
        }
        _ => Err(step),
    }
}

fn text(bytes: &[u8]) -> &str {
    core::str::from_utf8(bytes).unwrap_or("?")
}

fn read_all(handle: u64, buffer: &mut [u8]) -> Result<usize, &'static str> {
    read_to_end(Pipe::from_raw(handle), buffer).map_err(|_| "read child output")
}

fn matrix(console: Console, channel: &Channel) -> Result<(), &'static str> {
    // The worker itself cannot start anything.
    if spawn(program::EXIT7).map(|_| ()) != Err(Error::Rights) {
        return Err("worker spawn right");
    }
    let _ = absd_user::cprintln!(console, "BROKER PROBE worker-spawn=refused");

    // Refusals spend nothing: an unknown path, a fixed argument that does
    // not match, a missing argument, and slots that do not exist.
    channel
        .send(0, b"/owners/other", &[b"echo", b"x"])
        .map_err(|_| "send")?;
    expect(
        channel,
        REPLY_REFUSED,
        0,
        REFUSED_NOT_PERMITTED,
        "unknown path",
    )?;
    channel
        .send(0, b"/owners/echo", &[b"exit", b"x"])
        .map_err(|_| "send")?;
    expect(
        channel,
        REPLY_REFUSED,
        0,
        REFUSED_NOT_PERMITTED,
        "wrong fixed argument",
    )?;
    channel
        .send(0, b"/owners/echo", &[b"echo"])
        .map_err(|_| "send")?;
    expect(
        channel,
        REPLY_REFUSED,
        0,
        REFUSED_NOT_PERMITTED,
        "missing argument",
    )?;
    channel
        .send(9, b"/owners/echo", &[b"echo", b"x"])
        .map_err(|_| "send")?;
    expect(channel, REPLY_REFUSED, 9, REFUSED_SLOT, "slot out of range")?;
    // A program the kernel cannot load leaves the slot unspent.
    channel
        .send(0, b"/owners/legacy", &[])
        .map_err(|_| "send")?;
    expect(
        channel,
        REPLY_REFUSED,
        0,
        REFUSED_RESOURCES,
        "unstartable program",
    )?;
    let _ = absd_user::cprintln!(console, "BROKER PROBE refusals=5");

    // Slot 0: echo with a read-only block handle.
    channel
        .send(0, b"/owners/echo", &[b"echo", b"hello"])
        .map_err(|_| "send")?;
    let pid = expect(channel, REPLY_STARTED, 0, 0, "echo start")?;
    let (writer, stdout, stderr) = channel.slots[0];
    Pipe::from_raw(writer)
        .write_all(b"ping")
        .map_err(|_| "echo stdin")?;
    absd_user::close(writer).map_err(|_| "echo stdin close")?;
    let mut output = [0u8; 64];
    let out = read_all(stdout, &mut output)?;
    let mut errors = [0u8; 128];
    let err = read_all(stderr, &mut errors)?;
    let status = expect(channel, REPLY_EXITED, 0, 0, "echo exit")?;
    let _ = absd_user::cprintln!(
        console,
        "BROKER PROBE echo pid={} stdout={} status={status}",
        pid > 0,
        text(&output[..out])
    );
    // The child is on this boot: it reports the same boot identity.
    let own = absd_user::boot_id().map(|id| id[0] as u64 | (id[1] as u64) << 8);
    let mut expected = absd_user::LineBuffer::new();
    let _ = core::fmt::Write::write_fmt(&mut expected, format_args!("boot={:?}", own.ok()));
    let reported = text(&errors[..err]).trim_end();
    let shared = own.is_ok()
        && core::str::from_utf8(expected.as_bytes())
            .is_ok_and(|expected| reported.ends_with(expected));
    let reported = reported.split(" boot=").next().unwrap_or("?");
    let _ = absd_user::cprintln!(
        console,
        "BROKER PROBE echo stderr={reported} boot-shared={shared}"
    );
    // The spent slot cannot be used again: duplicate and stale requests.
    channel
        .send(0, b"/owners/echo", &[b"echo", b"again"])
        .map_err(|_| "send")?;
    expect(channel, REPLY_REFUSED, 0, REFUSED_SLOT, "spent slot")?;

    // Slot 1: a child that faults. Slot 2: an exit status.
    channel
        .send(1, b"/owners/fault", &[b"fault"])
        .map_err(|_| "send")?;
    expect(channel, REPLY_STARTED, 1, 0, "fault start")?;
    let fault = expect(channel, REPLY_EXITED, 1, 0, "fault exit")?;
    channel
        .send(2, b"/owners/exit", &[b"exit", b"7"])
        .map_err(|_| "send")?;
    expect(channel, REPLY_STARTED, 2, 0, "exit start")?;
    let exit = expect(channel, REPLY_EXITED, 2, 0, "exit exit")?;
    let _ = absd_user::cprintln!(console, "BROKER PROBE fault={fault} exit={exit}");

    // Slot 3: a child that is itself a requester, with its own policy.
    channel
        .send(3, b"/owners/nest", &[b"nest"])
        .map_err(|_| "send")?;
    expect(channel, REPLY_STARTED, 3, 0, "nest start")?;
    let (writer, stdout, _) = channel.slots[3];
    absd_user::close(writer).map_err(|_| "nest stdin close")?;
    let mut nested = [0u8; 96];
    let count = read_all(stdout, &mut nested)?;
    let status = expect(channel, REPLY_EXITED, 3, 0, "nest exit")?;
    let _ = absd_user::cprintln!(
        console,
        "BROKER PROBE nest status={status} {}",
        text(&nested[..count]).trim_end()
    );
    // Every slot is spent: the next request is refused.
    channel
        .send(3, b"/owners/exit", &[b"exit", b"0"])
        .map_err(|_| "send")?;
    expect(channel, REPLY_REFUSED, 3, REFUSED_SLOT, "exhausted slots")?;
    let _ = absd_user::cprintln!(console, "BROKER PROBE slots-exhausted=refused");
    Ok(())
}

/// Asks for more refusals than the reply pipe holds without reading any,
/// then reads: every reply is whole, and the channel then ends.
fn reply_flood(console: Console, channel: &Channel) -> i32 {
    for _ in 0..50 {
        if channel.send(9, b"/x", &[]).is_err() {
            return 81;
        }
    }
    // Let init answer everything, take the replies that fit whole (1024
    // bytes hold 42), then ask once more.
    let idle = Pipe::from_raw(channel.slots[0].1);
    let _ = idle.read_timeout(&mut [0u8; 1], 200);
    let mut whole = 0;
    while whole < 42
        && matches!(
            channel.next_reply(),
            Ok((REPLY_REFUSED, 9, REFUSED_SLOT, 0))
        )
    {
        whole += 1;
    }
    let _ = channel.send(9, b"/x", &[]);
    let _ = idle.read_timeout(&mut [0u8; 1], 200);
    let end = loop {
        match channel.next_reply() {
            Ok((REPLY_REFUSED, 9, REFUSED_SLOT, 0)) => whole += 1,
            Ok(_) | Err(Error::Invalid) => break "torn",
            Err(Error::BrokenPipe) => break "closed",
            Err(_) => break "error",
        }
    };
    let _ = absd_user::cprintln!(console, "BROKER PROBE reply-flood whole={whole} end={end}");
    0
}

/// Holds every pipe but three, so init can make a nested requester's
/// startup, request, and reply pipes but not its slot. The refusal must
/// leave init holding nothing: afterwards the worker can make exactly as
/// many pipes as before.
fn pipe_pressure(console: Console, channel: &Channel) -> i32 {
    let mut held = [0u64; 64];
    let fill = |held: &mut [u64; 64]| {
        let mut count = 0;
        while count < held.len() {
            match Pipe::create() {
                Ok(pipe) => {
                    held[count] = pipe.raw();
                    count += 1;
                }
                Err(_) => break,
            }
        }
        count
    };
    let before = fill(&mut held);
    if before < 3 {
        return 82;
    }
    for &pipe in &held[before - 3..before] {
        let _ = absd_user::close(pipe);
    }
    let refused = channel.send(0, b"/owners/nest", &[b"nest"]).is_ok()
        && matches!(
            channel.next_reply(),
            Ok((REPLY_REFUSED, 0, REFUSED_RESOURCES, _))
        );
    for &pipe in &held[..before - 3] {
        let _ = absd_user::close(pipe);
    }
    let after = fill(&mut held);
    for &pipe in &held[..after] {
        let _ = absd_user::close(pipe);
    }
    let _ = absd_user::cprintln!(
        console,
        "BROKER PROBE pipe-pressure refused={refused} recovered={}",
        after == before
    );
    0
}
