#![no_std]
#![no_main]

use absd_user::{Child, MultiStart, Outcome, Pipe, SpawnHandleCopy};
use readable_native_probe::{raw, wait};

static CHILD: &[u8] = include_bytes!(env!("READABLE_CHILD_ELF"));
absd_user::multi_entry!(main);

fn require(value: bool, code: i32) -> Result<(), i32> {
    if value { Ok(()) } else { Err(code) }
}

fn observe_waiting(child: Child) -> Result<(), i32> {
    let beginning = absd_user::time();
    loop {
        let info = absd_user::info(Some(child)).map_err(|_| 20)?;
        if info.state == absd_user::INFO_STATE_WAITING { return Ok(()); }
        require(info.state != absd_user::INFO_STATE_TERMINAL, 21)?;
        require(absd_user::time().saturating_sub(beginning) < 1000, 22)?;
        absd_user::sleep(1);
    }
}

fn positional_and_stale(first: Pipe) -> Result<(), i32> {
    let second = Pipe::create().map_err(|_| 80)?;
    let observed = (|| {
        require(second.write_timeout(b"X", 1000) == Ok(1), 81)?;
        require(wait(&[first.raw(), second.raw()], u64::MAX) == 2, 82)
    })();
    let closed = absd_user::close(second.raw()).is_ok();
    observed?;
    require(closed, 83)?;
    // Allocate again so the closed generation is tested beside a live handle.
    let replacement = Pipe::create().map_err(|_| 84)?;
    let observed = (|| {
        require(replacement.raw() != second.raw(), 85)?;
        require(wait(&[second.raw()], u64::MAX) == -9, 86)?;
        require(wait(&[replacement.raw()], u64::MAX) == 0, 87)
    })();
    let closed = absd_user::close(replacement.raw()).is_ok();
    observed.and_then(|()| require(closed, 88))
}

fn case(kind: u8) -> Result<(), i32> {
    let watch = Pipe::create().map_err(|_| 10)?;
    let ack = match Pipe::create() {
        Ok(pipe) => pipe,
        Err(_) => { let _ = absd_user::close(watch.raw()); return Err(11); }
    };
    let mut watched = Some(watch);
    let mut child = None;
    let result = (|| {
        let spawned = absd_user::spawn_image(CHILD, &[
            SpawnHandleCopy::new(watch.raw(), absd_user::RIGHT_READ),
            SpawnHandleCopy::new(ack.raw(), absd_user::RIGHT_WRITE),
        ], absd_user::SPAWN_NO_SPAWN).map_err(|_| 12)?;
        child = Some(spawned);
        let mut byte = [0];
        require(ack.read_timeout(&mut byte, 1000) == Ok(1) && byte == *b"A", 13)?;
        observe_waiting(spawned)?;
        match kind {
            b'D' => require(watch.write_timeout(b"X", 1000) == Ok(1), 30)?,
            b'E' => {
                absd_user::close(watch.raw()).map_err(|_| 31)?;
                watched = None;
            }
            b'K' => absd_user::kill(spawned).map_err(|_| 32)?,
            _ => return Err(33),
        }
        if kind != b'K' {
            require(ack.read_timeout(&mut byte, 1000) == Ok(1) && byte[0] == kind, 34)?;
        }
        let outcome = absd_user::wait_timeout(Some(spawned), 1000).map_err(|_| 35)?;
        child = None; // The successful wait reaped the process handle.
        require(outcome == if kind == b'K' { Outcome::Killed } else { Outcome::Exited(0) }, 36)?;
        if let Some(pipe) = watched {
            let info = pipe.info().map_err(|_| 37)?;
            require(info.readers == 1 && info.writers == 1, 38)?;
        }
        let info = ack.info().map_err(|_| 39)?;
        require(info.available == 0 && info.writers == 1, 40)?;
        if kind == b'K' {
            // A post-reap pipe event must not resurrect the retired waiter.
            require(watch.write_timeout(b"Z", 1000) == Ok(1), 41)?;
            require(ack.info().map_err(|_| 42)?.available == 0, 43)?;
        }
        Ok(())
    })();
    // Failed cases stay failed even when scoped cleanup succeeds.
    if let Some(child) = child {
        let _ = absd_user::kill(child);
        let _ = absd_user::wait_timeout(Some(child), 1000);
    }
    let closed_watch = watched.is_none_or(|pipe| absd_user::close(pipe.raw()).is_ok());
    let closed_ack = absd_user::close(ack.raw()).is_ok();
    result.and_then(|()| require(closed_watch && closed_ack, 44))
}

fn run(start: MultiStart<'_>) -> Result<(), i32> {
    let [input, output] = start.handles else { return Err(50); };
    require(*output == start.console.raw(), 51)?;
    // The external boot's input is deliberately empty. Drain EOF before
    // starting, so the canonical input producer has completed its contract.
    require(Pipe::from_raw(*input).read_timeout(&mut [0], 1000) == Ok(0), 52)?;
    let pipe = Pipe::create().map_err(|_| 53)?;
    let poll = wait(&[pipe.raw()], u64::MAX);
    if poll == -38 {
        require(wait(&[], absd_user::WAIT_READABLE_POLL) == -38, 65)?;
        absd_user::close(pipe.raw()).map_err(|_| 54)?;
        start.console.write_all(b"READABLE NATIVE ABSENT\n").map_err(|_| 55)?;
        return Ok(());
    }
    let direct = (|| {
        require(poll == 0, 56)?;
        require(wait(&[], 1) == -22, 57)?;
        require(wait(&[pipe.raw(); 12], u64::MAX) == -22, 64)?;
        require(raw(1, 1, 1) == -14, 58)?;
        positional_and_stale(pipe)?;
        let before = absd_user::time();
        require(wait(&[pipe.raw()], 1) == -110, 59)?;
        require(absd_user::time().saturating_sub(before) >= 2, 60)
    })();
    let closed = absd_user::close(pipe.raw()).is_ok();
    direct?;
    require(closed, 61)?;
    for (kind, marker) in [(b'D', b"READABLE DATA PASS\n" as &[u8]),
                          (b'E', b"READABLE EOF PASS\n"), (b'K', b"READABLE KILL PASS\n")] {
        case(kind)?;
        start.console.write_all(marker).map_err(|_| 62)?;
    }
    start.console.write_all(b"READABLE NATIVE PASS\n").map_err(|_| 63)
}

fn main(start: MultiStart<'_>) -> i32 {
    match run(start) { Ok(()) => 0, Err(code) => code }
}
