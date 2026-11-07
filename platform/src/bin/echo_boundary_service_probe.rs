#![feature(restricted_std)]
//! Opt-in native boundary fixture; production Owner and Channel are unchanged.
#[path = "../echo_boundary.rs"]
mod fixture;
use absd_net::{
    Config, NicLink,
    echo::{self, Channel, KernelPipe, Owner, Pipe},
};
use absd_runtime::{
    RIGHT_READ, RIGHT_WRITE, ResourceCensus,
    process::{SPAWN_NO_SPAWN, spawn_image_raw},
};
use std::{cell::Cell, rc::Rc};
type NativeOwner = Owner<fixture::CountedLink<NicLink>>;
fn sys(n: u64, a: u64, b: u64, c: u64) -> i64 {
    let out: i64;
    unsafe {
        core::arch::asm!("int 0x80", inlateout("rax") n => out, in("rdi") a, in("rsi") b, in("rdx") c, options(nostack, preserves_flags));
    }
    out
}
struct Handle(u64);
impl Drop for Handle {
    fn drop(&mut self) {
        if self.0 != 0 {
            let _ = absd_runtime::close(self.0);
        }
    }
}
fn handle(n: i64) -> Result<Handle, String> {
    if n < 0 {
        Err(format!("kernel {n}"))
    } else {
        Ok(Handle(n as u64))
    }
}
fn pipe() -> Result<(Handle, Handle), String> {
    let both = handle(sys(16, 0, 0, 0))?;
    let reader =
        Handle(absd_runtime::duplicate(both.0, RIGHT_READ).map_err(|e| format!("reader {e}"))?);
    let writer =
        Handle(absd_runtime::duplicate(both.0, RIGHT_WRITE).map_err(|e| format!("writer {e}"))?);
    Ok((reader, writer))
}
struct Child(Handle);
impl Child {
    fn wait(&mut self, ticks: u64) -> Result<Option<[u64; 4]>, String> {
        let mut record = [0; 4];
        let n = sys(6, self.0.0, record.as_mut_ptr() as u64, ticks);
        if n >= 0 {
            self.0.0 = 0;
            Ok(Some(record))
        } else if n == -110 {
            Ok(None)
        } else {
            Err(format!("wait {n}"))
        }
    }
}
impl Drop for Child {
    fn drop(&mut self) {
        if self.0.0 != 0 {
            let _ = sys(20, self.0.0, 0, 0);
            let mut record = [0u64; 4];
            if sys(6, self.0.0, record.as_mut_ptr() as u64, 1000) >= 0 {
                self.0.0 = 0;
            }
        }
    }
}
fn check(last: &mut u64, whole: u64, until: u64) -> Result<u64, String> {
    let now = absd_runtime::boot_millis();
    fixture::clock(last, whole.min(until), now)?;
    Ok(now)
}
fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}
fn census(label: &str) -> Result<ResourceCensus, String> {
    let c = absd_runtime::resource_census().map_err(|e| format!("census {e}"))?;
    println!(
        "ECHO BOUNDARY CENSUS v=1 label={label} processes={} handles={} pipes={} cells={} frames={}",
        c.processes, c.handles, c.pipes, c.cells, c.frames
    );
    Ok(c)
}
fn restored(before: ResourceCensus, after: ResourceCensus) -> bool {
    (before.processes, before.handles, before.pipes, before.cells)
        == (after.processes, after.handles, after.pipes, after.cells)
}
struct Session {
    child: Child,
    pipe: fixture::ObservedPipe<KernelPipe>,
    result: Handle,
}
fn spawn(
    image: &[u8],
    name: &[u8],
    until: u64,
    whole: u64,
    last: &mut u64,
    negative: bool,
) -> Result<Session, String> {
    check(last, whole, until)?;
    let (child_in, parent_out) = pipe()?;
    let (parent_in, child_out) = pipe()?;
    let (result_in, result_out) = pipe()?;
    let (startup_in, startup_out) = pipe()?;
    let copies = [
        [startup_in.0, RIGHT_READ, 0],
        [child_in.0, RIGHT_READ, 0],
        [child_out.0, RIGHT_WRITE, 0],
        [result_out.0, RIGHT_WRITE, 0],
        [child_out.0, RIGHT_WRITE, 1],
    ];
    let mut startup = [0; absd_broker::MAX_STARTUP];
    let length = absd_broker::encode_startup(
        &[
            (absd_broker::role::STDIN, 1),
            (absd_broker::role::STDOUT, 2),
            (absd_broker::role::STDERR, 3),
        ],
        [],
        [],
        b"/",
        name,
        copies.len(),
        &mut startup,
    )
    .map_err(|e| format!("startup {e:?}"))?;
    let request = [
        image.as_ptr() as u64,
        image.len() as u64,
        copies.as_ptr() as u64,
        copies.len() as u64,
    ];
    let child = Child(handle(spawn_image_raw(
        request.as_ptr() as u64,
        SPAWN_NO_SPAWN,
        0,
    ))?);
    check(last, whole, until)?;
    drop((startup_in, child_in, child_out, result_out));
    let now = check(last, whole, until)?;
    absd_runtime::write_within(
        startup_out.0,
        &startup[..length],
        (until.min(whole) - now).min(1000),
    )
    .map_err(|e| format!("startup write {e}"))?;
    check(last, whole, until)?;
    drop(startup_out);
    let mut bootstrap = [1, 192, 0, 2, 1, 0, 0, 0, 0, 0, 0, 0, 0];
    bootstrap[5..].copy_from_slice(&until.to_be_bytes());
    let now = check(last, whole, until)?;
    absd_runtime::write_within(parent_out.0, &bootstrap, (until.min(whole) - now).min(1000))
        .map_err(|e| format!("bootstrap {e}"))?;
    check(last, whole, until)?;
    if negative {
        println!(
            "ECHO BOUNDARY BOOTSTRAP v=1 bytes=13 hex={}",
            hex(&bootstrap)
        );
    }
    let transport = KernelPipe {
        request_reader: parent_in.0,
        reply_writer: parent_out.0,
    };
    core::mem::forget((parent_in, parent_out));
    Ok(Session {
        child,
        pipe: fixture::ObservedPipe::new(transport, if negative { Some(56) } else { None }),
        result: result_in,
    })
}
fn result_read(
    session: &Session,
    output: &mut Vec<u8>,
    eof: &mut bool,
    last: &mut u64,
    whole: u64,
    until: u64,
) -> Result<(), String> {
    check(last, whole, until)?;
    let mut bytes = [0; 256];
    let result = absd_runtime::read_within(session.result.0, &mut bytes, 1);
    check(last, whole, until)?;
    match result {
        Ok(0) => *eof = true,
        Ok(n) if n <= bytes.len() && output.len() + n <= 2048 => {
            output.extend_from_slice(&bytes[..n])
        }
        Err(-110 | -11) => {}
        other => return Err(format!("result read {other:?}")),
    }
    Ok(())
}
fn negative(
    owner: &mut NativeOwner,
    endpoint: echo::Endpoint,
    until: u64,
    whole: u64,
    last: &mut u64,
    sends: &Cell<u64>,
) -> Result<(), String> {
    let mut channel =
        Channel::new(owner, endpoint).map_err(|e| format!("negative channel {e:?}"))?;
    let mut session = spawn(
        include_bytes!(env!("ABSD_ECHO_BOUNDARY_CLIENT_ELF")),
        b"echo-boundary-client",
        until,
        whole,
        last,
        true,
    )?;
    let pre_poll = loop {
        let before = check(last, whole, until)?;
        let live = channel.poll(owner, &mut session.pipe);
        check(last, whole, until)?;
        if !live || session.pipe.eof.is_some() || owner.socket_count() != 1 {
            return Err("negative retired before prefix".into());
        }
        if let Some(stamp) = session.pipe.prefix {
            if stamp.bytes != 1
                || !fixture::ledger_matches(&session.pipe.input, &session.pipe.output)
                || stamp.before < before
                || stamp.after < stamp.before
                || !fixture::before_frame(before, until, stamp.after)
                || sends.get() != 0
            {
                return Err("negative literal ledger/prefix/send mismatch".into());
            }
            println!(
                "ECHO BOUNDARY PREFIX v=1 before_ms={before} read_before_ms={} read_ms={} bytes=1 hex=00 sockets=1",
                stamp.before, stamp.after
            );
            break before;
        }
    };
    let kill_before = check(last, whole, until)?;
    let killed = sys(20, session.child.0.0, 0, 0);
    let kill_at = check(last, whole, until)?;
    if killed != 0 || !fixture::before_frame(pre_poll, until, kill_at) {
        return Err(format!("negative kill {killed}"));
    }
    println!("ECHO BOUNDARY KILL v=1 before_ms={kill_before} at_ms={kill_at} code={killed}");
    let reap_before = check(last, whole, until)?;
    if !fixture::before_frame(pre_poll, until, reap_before) {
        return Err("negative frame deadline before reap".into());
    }
    let remaining = pre_poll
        .checked_add(echo::FRAME_MS)
        .ok_or("frame overflow")?
        .min(until)
        .min(whole)
        .checked_sub(reap_before)
        .filter(|n| *n > 0)
        .ok_or("negative reap has no remaining time")?;
    let outcome = session
        .child
        .wait(remaining.min(10))?
        .ok_or("negative reap timeout")?;
    let reap_at = check(last, whole, until)?;
    if outcome != [3, 0, 0, 0] || !fixture::before_frame(pre_poll, until, reap_at) {
        return Err(format!("negative reap {outcome:?}"));
    }
    println!(
        "ECHO BOUNDARY REAP v=1 before_ms={reap_before} at_ms={reap_at} kind={} status={}",
        outcome[0], outcome[1]
    );
    let mut result_eof = false;
    let mut result = Vec::new();
    loop {
        let now = check(last, whole, until)?;
        if !fixture::before_frame(pre_poll, until, now) {
            return Err("negative EOF frame deadline".into());
        }
        let live = channel.poll(owner, &mut session.pipe);
        let after = check(last, whole, until)?;
        if !fixture::before_frame(pre_poll, until, after) {
            return Err("negative EOF after frame deadline".into());
        }
        if let Some(stamp) = session.pipe.eof {
            if live
                || owner.socket_count() != 0
                || stamp.after < stamp.before
                || stamp.before < reap_at
                || !fixture::before_frame(pre_poll, until, stamp.after)
            {
                return Err("not actual EOF retirement".into());
            }
            println!(
                "ECHO BOUNDARY EOF v=1 before_ms={} at_ms={} bytes=0",
                stamp.before, stamp.after
            );
            break;
        }
        if !live {
            return Err("negative fallback/timeout without EOF".into());
        }
    }
    while !result_eof {
        result_read(&session, &mut result, &mut result_eof, last, whole, until)?;
        if !fixture::before_frame(pre_poll, until, *last) {
            return Err("negative result EOF frame deadline".into());
        }
    }
    if !result.is_empty()
        || sends.get() != 0
        || !fixture::ledger_matches(&session.pipe.input, &session.pipe.output)
    {
        return Err(format!(
            "negative diagnostic or changed ledger {}",
            String::from_utf8_lossy(&result)
        ));
    }
    let stale = owner
        .start(endpoint, fixture::PEER)
        .err()
        .ok_or("negative endpoint revived")?;
    let at = check(last, whole, until)?;
    if stale != echo::Error::Stale || !fixture::before_frame(pre_poll, until, at) {
        return Err("negative stale/time".into());
    }
    println!(
        "ECHO BOUNDARY LEDGER v=1 read_bytes={} read_hex={} written_bytes={} written_hex={} link_sends={}",
        session.pipe.input.len(),
        hex(&session.pipe.input),
        session.pipe.output.len(),
        hex(&session.pipe.output),
        sends.get()
    );
    println!(
        "ECHO BOUNDARY RETIRED v=1 at_ms={at} request_eof=1 result_eof=1 channel=0 sockets=0 fallback=0 stale_code={}",
        stale.code()
    );
    Ok(())
}
fn positive(
    owner: &mut NativeOwner,
    old: echo::Endpoint,
    whole: u64,
    last: &mut u64,
) -> Result<String, String> {
    let start = check(last, whole, whole)?;
    let until = start
        .checked_add(echo::MAX_LIFETIME_MS)
        .ok_or("positive overflow")?;
    if until > whole {
        return Err("positive cannot fit whole bound".into());
    }
    let endpoint = owner
        .grant(fixture::PEER, until, |b| {
            getrandom_0_2::getrandom(b).map_err(|_| -5)
        })
        .map_err(|e| format!("positive grant {e:?}"))?;
    if endpoint == old
        || owner.start(old, fixture::PEER) != Err(echo::Error::Stale)
        || owner.socket_count() != 1
    {
        return Err("positive freshness".into());
    }
    check(last, whole, until)?;
    println!("ECHO BOUNDARY POSITIVE v=1 start_ms={start} until_ms={until} fresh=1 sockets=1");
    let mut channel =
        Channel::new(owner, endpoint).map_err(|e| format!("positive channel {e:?}"))?;
    let mut session = spawn(
        include_bytes!(env!("ABSD_PING_CLIENT_ELF")),
        b"ping-once",
        until,
        whole,
        last,
        false,
    )?;
    let mut output = Vec::new();
    let mut result_eof = false;
    let mut outcome = None;
    let mut live = true;
    loop {
        check(last, whole, until)?;
        if live {
            live = channel.poll(owner, &mut session.pipe);
        }
        check(last, whole, until)?;
        if live {
            owner.poll().map_err(|e| format!("positive poll {e:?}"))?;
        }
        check(last, whole, until)?;
        result_read(&session, &mut output, &mut result_eof, last, whole, until)?;
        if outcome.is_none() {
            check(last, whole, until)?;
            outcome = session.child.wait(1)?;
            check(last, whole, until)?;
            if outcome.is_some_and(|r| r != [1, 0, 0, 0]) {
                return Err(format!(
                    "positive child {outcome:?} {}",
                    String::from_utf8_lossy(&output)
                ));
            }
        }
        if outcome.is_some() && !live {
            // A CLOSE acknowledgement can finish Channel before the OS pipe EOF.
            // Read the actual pipe after normal reap; no synthetic EOF is inserted.
            if session.pipe.eof.is_none() {
                let mut bytes = [0; 8];
                check(last, whole, until)?;
                let read = session
                    .pipe
                    .read(&mut bytes)
                    .map_err(|e| format!("positive EOF {e}"))?;
                check(last, whole, until)?;
                if read.is_some_and(|n| n != 0) {
                    return Err("positive extra protocol bytes".into());
                }
            }
            if session.pipe.eof.is_some() && result_eof {
                break;
            }
        }
        absd_runtime::sleep_ticks(1);
        check(last, whole, until)?;
    }
    let text = String::from_utf8(output).map_err(|_| "positive result UTF8")?;
    if text.lines().count() != 1
        || !text.starts_with("PING peer=192.0.2.1 identifier=")
        || !text.ends_with(" auth=none denied=1 nic=0 requests=1\n")
        || owner.socket_count() != 0
    {
        return Err(format!("positive result/retirement {text}"));
    }
    let at = check(last, whole, until)?;
    println!(
        "ECHO BOUNDARY POSITIVE-REAP v=1 at_ms={at} kind=1 status=0 request_eof=1 result_eof=1"
    );
    Ok(text)
}
fn run() -> Result<(), String> {
    let start = absd_runtime::boot_millis();
    let whole = start
        .checked_add(fixture::WHOLE_MS)
        .ok_or("whole overflow")?;
    let negative_until = start
        .checked_add(echo::MAX_LIFETIME_MS)
        .ok_or("negative overflow")?;
    let mut last = start;
    absd_runtime::link_anchor();
    let sends = Rc::new(Cell::new(0));
    let link = fixture::CountedLink {
        inner: NicLink::from_startup().map_err(|e| format!("NIC {e:?}"))?,
        sends: sends.clone(),
    };
    let mut owner = Owner::open(
        link,
        Config {
            address: [192, 0, 2, 100].into(),
            prefix_len: 24,
            gateway: None,
            rx_buffer: 1024,
            tx_buffer: 1024,
        },
    )
    .map_err(|e| format!("owner {e:?}"))?;
    check(&mut last, whole, negative_until)?;
    println!(
        "ECHO BOUNDARY BEGIN v=1 start_ms={start} until_ms={whole} negative_until_ms={negative_until}"
    );
    let now = check(&mut last, whole, negative_until)?;
    let (rows, closed) = fixture::constructors(&mut owner, now, negative_until, |b| {
        getrandom_0_2::getrandom(b).map_err(|_| -5)
    })?;
    check(&mut last, whole, negative_until)?;
    for (case, code, sockets) in rows {
        println!("ECHO BOUNDARY CTOR v=1 case={case} code={code} sockets={sockets}");
    }
    if sends.get() != 0 {
        return Err("constructor sent frame".into());
    }
    let before = census("before-negative")?;
    let endpoint = owner
        .grant(fixture::PEER, negative_until, |b| {
            getrandom_0_2::getrandom(b).map_err(|_| -5)
        })
        .map_err(|e| format!("negative grant {e:?}"))?;
    if endpoint == closed {
        return Err("constructor epoch reused".into());
    }
    negative(
        &mut owner,
        endpoint,
        negative_until,
        whole,
        &mut last,
        &sends,
    )?;
    let after = census("after-negative")?;
    if !restored(before, after) {
        return Err("negative owned object census".into());
    }
    check(&mut last, whole, whole)?;
    let text = positive(&mut owner, endpoint, whole, &mut last)?;
    let after_positive = census("after-positive")?;
    if !restored(before, after_positive) || owner.socket_count() != 0 {
        return Err("positive owned object census".into());
    }
    let at = check(&mut last, whole, whole)?;
    println!("ECHO BOUNDARY DONE v=1 at_ms={at} objects_restored=1 sockets=0");
    print!("{text}");
    println!("PING DONE child=exited sockets=0 requests=1");
    check(&mut last, whole, whole)?;
    Ok(())
}
fn main() -> std::process::ExitCode {
    match run() {
        Ok(()) => std::process::ExitCode::SUCCESS,
        Err(error) => {
            println!("ECHO BOUNDARY ERROR {error}");
            std::process::ExitCode::from(1)
        }
    }
}
