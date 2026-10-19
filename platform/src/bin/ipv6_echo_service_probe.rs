#![feature(restricted_std)]
//! Sole NIC owner for DAD then one delegated outbound IPv6 Echo diagnostic.
use absd_net::{
    FRAME_MAX, Link, LinkReading, NicLink,
    ipv6::{
        channel::KernelPipe,
        dad,
        echo::{self, Channel, Owner},
    },
};
use std::{cell::RefCell, fmt::Write as _, rc::Rc};

// Probe-only observations. The owner/Guarded/engine path retains every check;
// no logging or extra NIC operation occurs inside the delegated send call.
struct Submission {
    before_ms: u64,
    after_ms: u64,
    result: Result<(), i64>,
    frame: Vec<u8>,
}
#[derive(Default)]
struct Trace {
    attempts: u64,
    first: Option<Submission>,
}
struct ObservedLink {
    inner: NicLink,
    trace: Rc<RefCell<Trace>>,
}
impl Link for ObservedLink {
    fn mac(&self) -> [u8; 6] {
        self.inner.mac()
    }
    fn send(&mut self, frame: &[u8]) -> Result<(), i64> {
        if frame.len() < 55 || frame[12..14] != [0x86, 0xdd] || frame[20] != 58 || frame[54] != 128
        {
            return self.inner.send(frame);
        }
        let before_ms = absd_runtime::boot_millis();
        let result = self.inner.send(frame);
        let after_ms = absd_runtime::boot_millis();
        let mut trace = self.trace.borrow_mut();
        trace.attempts = trace.attempts.saturating_add(1);
        if trace.first.is_none() {
            trace.first = Some(Submission {
                before_ms,
                after_ms,
                result,
                frame: frame.to_vec(),
            });
        }
        result
    }
    fn receive(
        &mut self,
        buffer: &mut [u8; FRAME_MAX],
        timeout_ms: u64,
    ) -> Result<Option<usize>, i64> {
        self.inner.receive(buffer, timeout_ms)
    }
    fn now_ms(&self) -> u64 {
        self.inner.now_ms()
    }
    fn pause(&self, ms: u64) {
        self.inner.pause(ms)
    }
    fn link_up(&self) -> bool {
        self.inner.link_up()
    }
    fn disabled(&self) -> bool {
        self.inner.disabled()
    }
    fn read(&self) -> Option<LinkReading> {
        self.inner.read()
    }
}
fn print_trace(trace: &Trace, terminal_ms: u64) {
    if let Some(first) = &trace.first {
        let mut frame = String::with_capacity(first.frame.len() * 2);
        for byte in &first.frame {
            let _ = write!(frame, "{byte:02x}");
        }
        println!(
            "PING6 SUBMISSION before_ms={} after_ms={} result={} frame={}",
            first.before_ms,
            first.after_ms,
            first.result.err().unwrap_or(0),
            frame
        );
    }
    println!(
        "PING6 TERMINAL boot_ms={terminal_ms} attempts={}",
        trace.attempts
    );
}
use absd_runtime::{
    RIGHT_READ, RIGHT_WRITE,
    process::{SPAWN_NO_SPAWN, spawn_image_raw},
};
struct Handle(u64);
impl Drop for Handle {
    fn drop(&mut self) {
        if self.0 != 0 {
            let _ = absd_runtime::close(self.0);
        }
    }
}
impl Handle {
    fn take(mut self) -> u64 {
        let h = self.0;
        self.0 = 0;
        h
    }
}

fn sys(n: u64, a: u64, b: u64, c: u64) -> i64 {
    let out: i64;
    unsafe {
        core::arch::asm!("int 0x80", inlateout("rax") n=>out,
        in("rdi") a, in("rsi") b, in("rdx") c, options(nostack,preserves_flags));
    }
    out
}
fn pipe() -> Result<(Handle, Handle), String> {
    let both = sys(16, 0, 0, 0);
    if both < 0 {
        return Err(format!("pipe {both}"));
    }
    let both = Handle(both as u64);
    let reader =
        Handle(absd_runtime::duplicate(both.0, RIGHT_READ).map_err(|e| format!("reader {e}"))?);
    let writer =
        Handle(absd_runtime::duplicate(both.0, RIGHT_WRITE).map_err(|e| format!("writer {e}"))?);
    Ok((reader, writer))
}

fn budget(until: u64, last: &mut u64) -> Result<u64, String> {
    let now = absd_runtime::boot_millis();
    if now < *last || now >= until {
        return Err("original invocation budget".into());
    }
    *last = now;
    Ok(until - now)
}
fn run() -> Result<(), String> {
    let start = absd_runtime::boot_millis();
    let until = start.checked_add(dad::TOTAL_MS).ok_or("clock overflow")?;
    absd_runtime::link_anchor();
    let link = NicLink::from_startup().map_err(|e| format!("NIC {e:?}"))?;
    let trace = Rc::new(RefCell::new(Trace::default()));
    let link = ObservedLink {
        inner: link,
        trace: trace.clone(),
    };
    let mut owner = Owner::acquire(link, start, getrandom_0_2::getrandom)
        .map_err(|e| format!("DAD acquisition refused {e:?}"))?;
    let endpoint = owner
        .grant(echo::fixture_peer(), getrandom_0_2::getrandom)
        .map_err(|e| format!("Echo grant {e:?}"))?;
    let mut channel =
        Channel::new(&mut owner, endpoint).map_err(|e| format!("Echo channel {e:?}"))?;
    let stop = owner.stop_ms();
    println!(
        "PING6 OWNER invocation_start_ms={start} invocation_until_ms={until} stop_ms={stop} current_ms={}",
        absd_runtime::boot_millis()
    );
    println!("PING6 DAD CLEAR local=fd00:ab5d::15 scope=1 auth=none uniqueness=unproven");
    let result = run_child(&mut owner, &mut channel, until, start);
    let terminal_ms = absd_runtime::boot_millis();
    owner.retire();
    print_trace(&trace.borrow(), terminal_ms);
    let last = result?;
    let mut last = last;
    budget(until, &mut last)?;
    if owner.socket_count() != 0 {
        return Err("retained socket".into());
    }
    let counts = owner.observations();
    println!(
        "PING6 SERVICE PASS child=exited sockets=0 probes={} defenses={} received={} malformed={}",
        counts.probes_submitted,
        counts.defenses_submitted,
        counts.received_frames,
        counts.malformed
    );
    Ok(())
}
fn run_child(
    owner: &mut Owner<ObservedLink>,
    channel: &mut Channel,
    until: u64,
    mut last: u64,
) -> Result<u64, String> {
    let image = include_bytes!(env!("ABSD_PING6_CLIENT_ELF"));
    let (child_in, parent_out) = pipe()?;
    let (parent_in, child_out) = pipe()?;
    let (result_reader, result_writer) = pipe()?;
    let (startup_reader, startup_writer) = pipe()?;
    let copies = [
        [startup_reader.0, RIGHT_READ, 0],
        [child_in.0, RIGHT_READ, 0],
        [child_out.0, RIGHT_WRITE, 0],
        [result_writer.0, RIGHT_WRITE, 0],
        [child_out.0, RIGHT_WRITE, 1],
    ];
    let original_start = until - dad::TOTAL_MS;
    let start_env = format!("ABSD_PING6_START_MS={original_start}");
    let stop_env = format!("ABSD_PING6_STOP_MS={}", owner.stop_ms());
    let mut record = [0; absd_broker::MAX_STARTUP];
    let n = absd_broker::encode_startup(
        &[
            (absd_broker::role::STDIN, 1),
            (absd_broker::role::STDOUT, 2),
            (absd_broker::role::STDERR, 3),
        ],
        core::iter::empty::<&[u8]>(),
        [start_env.as_bytes(), stop_env.as_bytes()],
        b"/",
        b"ping6-once",
        copies.len(),
        &mut record,
    )
    .map_err(|e| format!("startup {e:?}"))?;
    budget(until, &mut last)?;
    owner
        .check()
        .map_err(|e| format!("DAD before spawn {e:?}"))?;
    let req = [
        image.as_ptr() as u64,
        image.len() as u64,
        copies.as_ptr() as u64,
        copies.len() as u64,
    ];
    let process = spawn_image_raw(req.as_ptr() as u64, SPAWN_NO_SPAWN, 0);
    drop((startup_reader, child_in, child_out, result_writer));
    if process < 0 {
        return Err(format!("spawn {process}"));
    }
    let mut process = Handle(process as u64);
    let result = (|| {
        budget(until, &mut last)?;
        owner
            .check()
            .map_err(|e| format!("DAD after spawn {e:?}"))?;
        let r = absd_runtime::write_within(
            startup_writer.0,
            &record[..n],
            budget(until, &mut last)?.min(1000),
        );
        budget(until, &mut last)?;
        owner
            .check()
            .map_err(|e| format!("DAD after startup {e:?}"))?;
        r.map_err(|e| format!("startup write {e}"))?;
        drop(startup_writer);
        let bootstrap = owner
            .bootstrap()
            .map_err(|e| format!("DAD bootstrap {e:?}"))?;
        let r = absd_runtime::write_within(
            parent_out.0,
            &bootstrap,
            budget(until, &mut last)?.min(1000),
        );
        budget(until, &mut last)?;
        owner
            .check()
            .map_err(|e| format!("DAD after bootstrap {e:?}"))?;
        r.map_err(|e| format!("bootstrap write {e}"))?;
        let mut io = KernelPipe {
            request_reader: parent_in.take(),
            reply_writer: parent_out.take(),
        };
        let mut result = Vec::new();
        println!("PING6 SERVICE READY scope=1 peer=fd00:ab5d::2 requests=1");
        loop {
            budget(until, &mut last)?;
            let live = channel.poll(owner, &mut io);
            let mut bytes = [0; 256];
            let read = absd_runtime::read_within(result_reader.0, &mut bytes, 1);
            budget(until, &mut last)?;
            if live {
                owner
                    .check()
                    .map_err(|e| format!("DAD after result read {e:?}"))?;
            }
            match read {
                Ok(n) => {
                    if result.len() + n > 4096 {
                        return Err("result overflow".into());
                    }
                    result.extend_from_slice(&bytes[..n]);
                }
                Err(-110 | -11) => {}
                Err(e) => return Err(format!("result read {e}")),
            }
            let mut outcome = [0u64; 4];
            let waited = sys(
                6,
                process.0,
                outcome.as_mut_ptr() as u64,
                if live { 1 } else { 50 },
            );
            if waited >= 0 {
                process.0 = 0;
            }
            budget(until, &mut last)?;
            if live {
                owner.check().map_err(|e| format!("DAD after wait {e:?}"))?;
            }
            if waited >= 0 {
                loop {
                    budget(until, &mut last)?;
                    let r = absd_runtime::read_within(result_reader.0, &mut bytes, 1);
                    budget(until, &mut last)?;
                    if live {
                        owner
                            .check()
                            .map_err(|e| format!("DAD during terminal drain {e:?}"))?;
                    }
                    match r {
                        Ok(0) | Err(-110 | -11) => break,
                        Ok(n) if result.len() + n <= 4096 => result.extend_from_slice(&bytes[..n]),
                        _ => return Err("result drain".into()),
                    }
                }
                let text = String::from_utf8_lossy(&result);
                if outcome[0] != 1
                    || outcome[1] != 0
                    || !text.contains("PING6 OBSERVED peer=fd00:ab5d::2 scope=1")
                    || !text.contains("PING6 CLIENT AUTHORITY PASS nic=0 denied=1")
                {
                    return Err(format!("child status {}", outcome[1]));
                }
                print!("{text}");
                return Ok(last);
            }
            if !live {
                return Err("channel retired before child exit".into());
            }
            if waited != -110 {
                return Err(format!("wait {waited}"));
            }
            owner.wait().map_err(|e| format!("DAD wait {e:?}"))?;
        }
    })();
    owner.retire();
    if process.0 != 0 {
        let killed = sys(20, process.0, 0, 0);
        let mut outcome = [0u64; 4];
        let waited = sys(
            6,
            process.0,
            outcome.as_mut_ptr() as u64,
            if killed >= 0 { 0 } else { 1 },
        );
        if waited >= 0 {
            process.0 = 0;
        }
        if killed < 0 || waited < 0 {
            return Err(format!("child cleanup kill={killed} wait={waited}"));
        }
    }
    result
}
fn main() -> std::process::ExitCode {
    match run() {
        Ok(()) => std::process::ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("PING6 SERVICE ERROR {e}");
            std::process::ExitCode::from(1)
        }
    }
}
