use absd_user::mwm_protocol as protocol;
use absd_user::{
    Child, Console, Error, Outcome, Pipe, RIGHT_READ, RIGHT_WRITE, SPAWN_NO_SPAWN, SpawnHandleCopy,
    close, duplicate, kill, program, resource_census, spawn_many_copy, syscall3, time,
    wait_timeout,
};

const DISPLAY_OPEN: u64 = 0x7fd0;
const DISPLAY_INFO: u64 = 0x7fd1;
const WAIT_TICKS: u64 = 30_000;

pub fn run(console: Console) -> Result<(), &'static str> {
    let display = open()?;
    let (child, ready) = spawn(display, console)?;
    let first = (|| {
        readiness(ready)?;
        let second = unsafe { syscall3(DISPLAY_OPEN, 0, 0, 0) };
        if Error::from_code(second) != Error::Again {
            if second >= 0 {
                let _ = close(second as u64);
            }
            return Err("second display open");
        }
        console
            .write_str("MWM SECOND OPEN REFUSED error=-11\n")
            .map_err(|_| "second-open marker")?;
        kill(child).map_err(|_| "first MWM kill")?;
        wait_timeout(Some(child), WAIT_TICKS).map_err(|_| "first MWM reap")?;
        close(ready.raw()).map_err(|_| "first readiness close")?;
        census(1)?;
        console
            .write_str("MWM LAST CLOSE MASK\n")
            .map_err(|_| "mask marker")?;
        protocol::wait_ack(console, WAIT_TICKS)
    })();
    if let Err(step) = first {
        abort(child, ready);
        return Err(step);
    }

    let successor = open()?;
    let mut record = [0u8; 48];
    let raw = unsafe { syscall3(DISPLAY_INFO, successor, record.as_mut_ptr() as u64, 0) };
    if raw != 0 {
        close(successor).map_err(|_| "failed successor information close")?;
        return Err("successor information");
    }
    let info = match protocol::parse_info(&record) {
        Ok(info) => info,
        Err(step) => {
            let _ = close(successor);
            return Err(step);
        }
    };
    if info.generation != 2 || info.high_water != 0 {
        close(successor).map_err(|_| "wrong successor authority close")?;
        return Err("successor generation or high-water");
    }
    if console
        .write_str("MWM SUCCESSOR OPEN generation=2 high_water=0\n")
        .is_err()
    {
        let _ = close(successor);
        return Err("successor open marker");
    }
    let (child, ready) = spawn(successor, console)?;
    let second = (|| {
        let outcome = wait_timeout(Some(child), WAIT_TICKS * 2).map_err(|_| "successor wait")?;
        close(ready.raw()).map_err(|_| "successor readiness close")?;
        if outcome != Outcome::Exited(0) {
            return Err("successor outcome");
        }
        census(1)?;
        console
            .write_str("MWM DEMO OK processes=1\n")
            .map_err(|_| "success marker")
    })();
    if second.is_err() {
        abort(child, ready);
    }
    second
}

fn open() -> Result<u64, &'static str> {
    let handle = unsafe { syscall3(DISPLAY_OPEN, 0, 0, 0) };
    if handle > 0 {
        Ok(handle as u64)
    } else {
        Err("display open")
    }
}

fn spawn(display: u64, console: Console) -> Result<(Child, Pipe), &'static str> {
    let pipe = match Pipe::create() {
        Ok(pipe) => pipe,
        Err(_) => {
            let _ = close(display);
            return Err("readiness pipe");
        }
    };
    let reader = match duplicate(pipe.raw(), RIGHT_READ) {
        Ok(reader) => reader,
        Err(_) => {
            let _ = close(pipe.raw());
            let _ = close(display);
            return Err("readiness reader");
        }
    };
    let writer = match duplicate(pipe.raw(), RIGHT_WRITE) {
        Ok(writer) => writer,
        Err(_) => {
            let _ = close(reader);
            let _ = close(pipe.raw());
            let _ = close(display);
            return Err("readiness writer");
        }
    };
    if close(pipe.raw()).is_err() {
        let _ = close(reader);
        let _ = close(writer);
        let _ = close(display);
        return Err("readiness original close");
    }
    let copies = [
        SpawnHandleCopy::new(display, RIGHT_READ | RIGHT_WRITE),
        SpawnHandleCopy::new(writer, RIGHT_WRITE),
        SpawnHandleCopy::console(console.raw(), RIGHT_READ | RIGHT_WRITE),
    ];
    let spawned = spawn_many_copy(program::EXTERNAL_WORKLOAD | SPAWN_NO_SPAWN, &copies);
    let display_closed = close(display);
    let writer_closed = close(writer);
    let child = match spawned {
        Ok(child) => child,
        Err(_) => {
            let _ = close(reader);
            return Err("MWM spawn");
        }
    };
    if display_closed.is_err() || writer_closed.is_err() {
        let _ = kill(child);
        let _ = wait_timeout(Some(child), WAIT_TICKS);
        let _ = close(reader);
        let _ = close(display);
        let _ = close(writer);
        return Err("init display or readiness close");
    }
    Ok((child, Pipe::from_raw(reader)))
}

fn readiness(pipe: Pipe) -> Result<(), &'static str> {
    let deadline = time().saturating_add(WAIT_TICKS);
    let mut message = [0u8; 10];
    let mut length = 0;
    while length < message.len() {
        let remaining = deadline.saturating_sub(time());
        if remaining == 0 {
            return Err("readiness timeout");
        }
        let count = pipe
            .read_timeout(&mut message[length..], remaining)
            .map_err(|_| "readiness read")?;
        if count == 0 {
            return Err("readiness closed");
        }
        length += count;
    }
    if &message == b"MWM READY\n" {
        Ok(())
    } else {
        Err("readiness bytes")
    }
}

fn abort(child: Child, ready: Pipe) {
    let _ = kill(child);
    let _ = wait_timeout(Some(child), WAIT_TICKS);
    let _ = close(ready.raw());
}

fn census(expected: u64) -> Result<(), &'static str> {
    if resource_census().map_err(|_| "process census")?.processes == expected {
        Ok(())
    } else {
        Err("process cleanup")
    }
}
