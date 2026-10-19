#![feature(restricted_std)]
//! One selected TLS fixture per boot, using existing spawn and stream roles.

use absd_native_tls_fixture::fixture_cases;
use absd_native_tls_fixture::link_observer::{ObservedLink, Observer, WindowObservation};
use absd_net::datagram::channel::KernelPipe;
use absd_net::{Config, NicLink, Stack, datagram::Address, stream};
use absd_runtime::{
    RIGHT_READ, RIGHT_WRITE,
    process::{SPAWN_NO_SPAWN, spawn_image_raw},
};
use fixture_cases::Case;

const REPORT_LIMIT: usize = 65_536;

fn syscall(number: u64, a: u64, b: u64, c: u64) -> i64 {
    let result: i64;
    unsafe {
        core::arch::asm!(
            "int 0x80", inlateout("rax") number => result,
            in("rdi") a, in("rsi") b, in("rdx") c,
            options(nostack, preserves_flags),
        );
    }
    result
}

struct Handle(u64);
impl Handle {
    fn take(&mut self) -> u64 {
        std::mem::replace(&mut self.0, 0)
    }
}
impl Drop for Handle {
    fn drop(&mut self) {
        if self.0 != 0 {
            let _ = absd_runtime::close(self.take());
        }
    }
}

fn pipe() -> Result<(Handle, Handle), String> {
    let raw = syscall(16, 0, 0, 0);
    if raw < 0 {
        return Err(format!("pipe {raw}"));
    }
    let both = Handle(raw as u64);
    let reader = Handle(
        absd_runtime::duplicate(both.0, RIGHT_READ)
            .map_err(|error| format!("pipe reader {error}"))?,
    );
    let writer = Handle(
        absd_runtime::duplicate(both.0, RIGHT_WRITE)
            .map_err(|error| format!("pipe writer {error}"))?,
    );
    Ok((reader, writer))
}

struct Child {
    process: Option<u64>,
    pipe: Option<KernelPipe>,
    result_reader: Handle,
    result: Vec<u8>,
    killed: bool,
}
impl Child {
    fn kill(&mut self) -> Result<i64, String> {
        if self.killed {
            return Err("kill already requested".into());
        }
        let process = self.process.ok_or("child already reaped")?;
        let result = syscall(20, process, 0, 0);
        if result < 0 {
            return Err(format!("kill {result}"));
        }
        self.killed = true;
        Ok(result)
    }

    fn wait(&mut self, timeout: u64) -> Result<Option<[u64; 4]>, String> {
        let process = self.process.ok_or("child already reaped")?;
        let mut record = [0; 4];
        let result = syscall(6, process, record.as_mut_ptr() as u64, timeout);
        if result == -110 {
            return Ok(None);
        }
        if result < 0 {
            return Err(format!("wait {result}"));
        }
        // wait reaps the child and closes this exact process handle.
        self.process = None;
        Ok(Some(record))
    }

    fn read_report(&mut self) -> Result<usize, String> {
        let mut bytes = [0; 1024];
        match absd_runtime::read_within(self.result_reader.0, &mut bytes, 1) {
            Ok(length) => {
                if self
                    .result
                    .len()
                    .checked_add(length)
                    .is_none_or(|n| n > REPORT_LIMIT)
                {
                    return Err("child report bound".into());
                }
                self.result.extend_from_slice(&bytes[..length]);
                Ok(length)
            }
            Err(-110) => Ok(0),
            Err(error) => Err(format!("child report read {error}")),
        }
    }
}
impl Drop for Child {
    fn drop(&mut self) {
        // Failure paths retain exact ownership: close the native pipe, kill
        // only our child if still live, then reap before discarding its token.
        drop(self.pipe.take());
        if let Some(process) = self.process {
            let kill = self.kill();
            let wait = self.wait(1000);
            if !matches!(wait, Ok(Some(_))) {
                eprintln!(
                    "TLS CLEANUP process={} kill={:?} wait={:?}",
                    process, kill, wait
                );
                let _ = absd_runtime::close(process);
                self.process = None;
            }
        }
    }
}

fn spawn_child(case: Case, unix_seconds: u64, grant_expiry_ms: u64) -> Result<Child, String> {
    let image = include_bytes!(env!("ABSD_TLS_CLIENT_ELF"));
    let (child_in, mut parent_out) = pipe()?;
    let (mut parent_in, child_out) = pipe()?;
    let (result_reader, result_writer) = pipe()?;
    let (startup_reader, startup_writer) = pipe()?;
    let copies = [
        [startup_reader.0, RIGHT_READ, 0],
        [child_in.0, RIGHT_READ, 0],
        [child_out.0, RIGHT_WRITE, 0],
        [result_writer.0, RIGHT_WRITE, 0],
        // The fallback console is diagnostic output too. A second protocol
        // writer here would keep that pipe alive after NativeTransport drops.
        [result_writer.0, RIGHT_WRITE, 1],
    ];
    let time = if case.missing_time {
        "none".into()
    } else {
        unix_seconds.to_string()
    };
    let expiry = grant_expiry_ms.to_string();
    let body = case.expected_body.to_string();
    // The runtime supplies argv[0] from the startup record's program name.
    let args: [&[u8]; 8] = [
        b"--case",
        case.id.as_bytes(),
        b"--unix-time",
        time.as_bytes(),
        b"--grant-expiry",
        expiry.as_bytes(),
        b"--expected-body",
        body.as_bytes(),
    ];
    let mut startup = [0; absd_broker::MAX_STARTUP];
    let length = absd_broker::encode_startup(
        &[
            (absd_broker::role::STDIN, 1),
            (absd_broker::role::STDOUT, 2),
            (absd_broker::role::STDERR, 3),
        ],
        args,
        [],
        b"/",
        b"https-get",
        copies.len(),
        &mut startup,
    )
    .map_err(|error| format!("startup {error:?}"))?;
    let request = [
        image.as_ptr() as u64,
        image.len() as u64,
        copies.as_ptr() as u64,
        copies.len() as u64,
    ];
    let process = spawn_image_raw(request.as_ptr() as u64, SPAWN_NO_SPAWN, 0);
    if process < 0 {
        return Err(format!("spawn {process}"));
    }
    let child = Child {
        process: Some(process as u64),
        pipe: Some(KernelPipe {
            request_reader: parent_in.take(),
            reply_writer: parent_out.take(),
        }),
        result_reader,
        result: Vec::new(),
        killed: false,
    };
    // Parent copies of the child's protocol/result ends must disappear before
    // EOF can establish authority retirement. Only the child retains them.
    drop(startup_reader);
    drop(child_in);
    drop(child_out);
    drop(result_writer);
    absd_runtime::write_within(startup_writer.0, &startup[..length], 1000)
        .map_err(|error| format!("startup write {error}"))?;
    drop(startup_writer);
    Ok(child)
}

fn census(label: &str) -> Result<absd_runtime::ResourceCensus, String> {
    let resources = absd_runtime::resource_census().map_err(|error| format!("census {error}"))?;
    let frames = absd_runtime::frame_stats().map_err(|error| format!("frame stats {error}"))?;
    println!(
        "TLS SERVICE RESOURCES label={} processes={} handles={} pipes={} cells={} frames={} allocated_frames={} free_frames={} allocation_limit={:?} heap_pages={}",
        label,
        resources.processes,
        resources.handles,
        resources.pipes,
        resources.cells,
        resources.frames,
        frames.allocated_frames,
        frames.free_frames,
        frames.allocation_limit,
        absd_runtime::heap_mapped_pages(),
    );
    Ok(resources)
}

fn exhaustion<L: absd_net::Link>(stack: &mut Stack<L>, case: Case) -> Result<(), String> {
    let mut endpoints = Vec::new();
    let peer = Address {
        ip: [10, 0, 2, 2],
        port: 4443,
    };
    let result = (|| {
        for index in 0..stream::MAX_ENDPOINTS {
            endpoints.push(
                stack
                    .stream_grant(stream::Grant {
                        local_port: case.local_port + index as u16,
                        peer,
                        connect_timeout_ms: 2000,
                        lifetime_ms: 15_000,
                    })
                    .map_err(|error| format!("exhaustion setup {error:?}"))?,
            );
        }
        let before = stack.socket_count();
        let ninth = stack.stream_grant(stream::Grant {
            local_port: case.local_port + stream::MAX_ENDPOINTS as u16,
            peer,
            connect_timeout_ms: 2000,
            lifetime_ms: 15_000,
        });
        println!(
            "TLS GRANT CONTROL id={} result={:?} sockets_before={} sockets_after={}",
            case.id,
            ninth,
            before,
            stack.socket_count()
        );
        match ninth {
            Err(stream::Error::Exhausted)
                if endpoints.len() == stream::MAX_ENDPOINTS
                    && before == 0
                    && stack.socket_count() == before =>
            {
                Ok(())
            }
            Ok(endpoint) => {
                endpoints.push(endpoint);
                Err("grant table exceeded its bound".into())
            }
            _ => Err("grant exhaustion outcome".into()),
        }
    })();
    for endpoint in endpoints {
        let _ = stack.stream_abort(endpoint);
    }
    stack.poll();
    stack.poll();
    result
}

fn window_snapshot(case: Case, stage: &str, observer: &Observer) -> WindowObservation {
    let observation = observer.snapshot();
    println!(
        "TLS WINDOW SNAPSHOT id={} stage={} at_ms={} latest_window={:?} ack_events={} zero_events={} reopen_events={} first_zero_ms={:?} last_zero_ms={:?} last_ack_ms={:?} clock_refused={} counters_saturated={}",
        case.id,
        stage,
        absd_runtime::boot_millis(),
        observation.latest_window,
        observation.ack_events,
        observation.zero_events,
        observation.reopen_events,
        observation.first_zero_ms,
        observation.last_zero_ms,
        observation.last_ack_ms,
        observation.clock_refused,
        observation.counters_saturated,
    );
    observation
}

// L05 alone prepares this same Stack before its unchanged grant clock starts.
// ARP is unauthenticated neighbor data; readiness creates no endpoint authority.
const L05_PREP_MS: u64 = 2000;
const L05_PREP_CALLS: u32 = 8192;
const L05_PREP_FRAMES: u16 = 64;
const L05_PREP_POLLS: usize = 4096;

#[derive(Clone, Copy, Default)]
struct ArpPreparation {
    attempted: bool,
    armed: bool,
    station: [u8; 6],
    last: u64,
    until: u64,
    missed: u64,
    calls: u32,
    frames: u16,
    reply: Option<([u8; 6], u64)>,
    refused: Option<&'static str>,
}

#[derive(Clone, Default)]
struct ArpReadiness(std::rc::Rc<std::cell::Cell<ArpPreparation>>);
impl ArpReadiness {
    fn refuse(&self, reason: &'static str) {
        let mut state = self.0.get();
        state.refused.get_or_insert(reason);
        self.0.set(state);
    }

    fn check<L: absd_net::Link>(&self, link: &L) -> Result<(), i64> {
        let mut state = self.0.get();
        if !state.armed {
            return Ok(());
        }
        if state.refused.is_some() {
            return Err(-5);
        }
        let reading = link.read();
        let now = link.now_ms();
        state.refused = if now < state.last {
            Some("preparation clock rewind")
        } else if now >= state.until {
            Some("preparation deadline")
        } else {
            match reading {
                None => Some("preparation link unknown"),
                Some(r) if r.disabled || !r.link_up => Some("preparation link unavailable"),
                Some(r) if r.rx_missed != state.missed => Some("preparation missed frames"),
                Some(_) => None,
            }
        };
        state.last = now;
        self.0.set(state);
        if state.refused.is_some() {
            Err(-5)
        } else {
            Ok(())
        }
    }

    fn call(&self) -> Result<(), i64> {
        let mut state = self.0.get();
        if state.armed {
            if state.calls >= L05_PREP_CALLS {
                self.refuse("preparation I/O work bound");
                return Err(-5);
            }
            state.calls += 1;
            self.0.set(state);
        }
        Ok(())
    }

    fn received(&self, frame: &[u8]) {
        let mut state = self.0.get();
        if !state.armed || state.refused.is_some() {
            return;
        }
        if state.frames >= L05_PREP_FRAMES {
            self.refuse("preparation frame work bound");
            return;
        }
        state.frames += 1;
        if frame.len() < 14 {
            state.refused = Some("preparation short Ethernet frame");
        } else if frame[12..14] == [8, 6] {
            // This controlled preflight permits only the genuine exact reply.
            // Every received byte still goes unchanged to the existing engine.
            match l05_arp_reply(frame, state.station) {
                Some(mac) if state.reply.is_none_or(|(old, _)| old == mac) => {
                    state.reply.get_or_insert((mac, state.last));
                }
                _ => state.refused = Some("preparation ARP reply profile"),
            }
        }
        self.0.set(state);
    }
}

struct PreparationLink<L> {
    inner: L,
    readiness: Option<ArpReadiness>,
}
impl<L: absd_net::Link> absd_net::Link for PreparationLink<L> {
    fn mac(&self) -> [u8; 6] {
        self.inner.mac()
    }
    fn send(&mut self, frame: &[u8]) -> Result<(), i64> {
        if let Some(r) = &self.readiness {
            r.check(&self.inner)?;
            r.call()?;
        }
        let result = self.inner.send(frame);
        if let Some(r) = &self.readiness {
            if r.0.get().armed && result.is_err() {
                r.refuse("preparation send uncertain");
            }
            let _ = r.check(&self.inner);
        }
        result
    }
    fn receive(
        &mut self,
        buffer: &mut [u8; absd_net::FRAME_MAX],
        timeout: u64,
    ) -> Result<Option<usize>, i64> {
        if let Some(r) = &self.readiness {
            r.check(&self.inner)?;
            r.call()?;
        }
        let result = self.inner.receive(buffer, timeout);
        if let Some(r) = &self.readiness
            && r.0.get().armed
        {
            if result.is_err() {
                r.refuse("preparation receive uncertain");
            }
            let _ = r.check(&self.inner);
            if let Ok(Some(n)) = result {
                if n > buffer.len() {
                    r.refuse("preparation invalid receive length");
                    return Err(-5);
                }
                r.received(&buffer[..n]);
            }
        }
        result
    }
    fn now_ms(&self) -> u64 {
        self.inner.now_ms()
    }
    fn pause(&self, ms: u64) {
        if let Some(r) = &self.readiness {
            if r.check(&self.inner).is_err() {
                return;
            }
        }
        self.inner.pause(ms);
        if let Some(r) = &self.readiness {
            let _ = r.check(&self.inner);
        }
    }
    fn link_up(&self) -> bool {
        self.inner.link_up()
    }
    fn disabled(&self) -> bool {
        self.inner.disabled()
    }
    fn read(&self) -> Option<absd_net::LinkReading> {
        self.inner.read()
    }
}

fn l05_arp_request(station: [u8; 6]) -> [u8; 60] {
    let mut frame = [0; 60];
    frame[..6].fill(255);
    frame[6..12].copy_from_slice(&station);
    frame[12..22].copy_from_slice(&[8, 6, 0, 1, 8, 0, 6, 4, 0, 1]);
    frame[22..28].copy_from_slice(&station);
    frame[28..32].copy_from_slice(&[10, 0, 2, 15]);
    frame[32..38].fill(255);
    frame[38..42].copy_from_slice(&[10, 0, 2, 2]);
    frame
}

fn l05_arp_reply(frame: &[u8], station: [u8; 6]) -> Option<[u8; 6]> {
    if !matches!(frame.len(), 42 | 60)
        || frame[42..].iter().any(|b| *b != 0)
        || frame[..6] != station
        || frame[12..22] != [8, 6, 0, 1, 8, 0, 6, 4, 0, 2]
        || frame[6] & 1 != 0
        || frame[6..12] == [0; 6]
        || frame[6..12] == station
        || frame[6..12] != frame[22..28]
        || frame[28..32] != [10, 0, 2, 2]
        || frame[32..38] != station
        || frame[38..42] != [10, 0, 2, 15]
    {
        return None;
    }
    frame[6..12].try_into().ok()
}

fn prepare_l05<L: absd_net::Link>(
    stack: &mut Stack<L>,
    readiness: &ArpReadiness,
) -> Result<(), String> {
    let start = stack.link().now_ms();
    let until = start
        .checked_add(L05_PREP_MS)
        .ok_or("preparation overflow")?;
    let reading = stack
        .read_link()
        .ok_or("preparation initial link unknown")?;
    let station = stack.mac();
    let link_errors = stack.stats().link_errors;
    if readiness.0.get().attempted
        || stack.socket_count() != 0
        || station[0] & 1 != 0
        || station == [0; 6]
        || !reading.link_up
        || reading.disabled
    {
        return Err("preparation initial refusal".into());
    }
    readiness.0.set(ArpPreparation {
        attempted: true,
        armed: true,
        station,
        last: start,
        until,
        missed: reading.rx_missed,
        ..ArpPreparation::default()
    });
    let check = |stack: &Stack<L>| {
        if stack.stats().link_errors != link_errors {
            readiness.refuse("preparation stack link errors");
        }
        readiness
            .check(stack.link())
            .map_err(|_| format!("L05 ARP preparation {:?}", readiness.0.get().refused))
    };
    let result = (|| {
        check(stack)?;
        // One submission only. Err may already have a first effect; no retry.
        stack
            .raw_send(&l05_arp_request(station))
            .map_err(|e| format!("preparation send {e:?}"))?;
        check(stack)?;
        for _ in 0..L05_PREP_POLLS {
            check(stack)?;
            stack.poll();
            check(stack)?;
            let state = readiness.0.get();
            if let Some((peer_mac, received_ms)) = state.reply {
                // wait() can retain a reply, but only this completed poll
                // allows the pinned process_arp path to fill this same cache.
                if stack.socket_count() != 0 {
                    return Err("preparation socket appeared".into());
                }
                println!(
                    "TLS L05 ARP PREPARED start_ms={} reply_ms={} poll_complete_ms={} peer_mac={:02x?} frames={} calls={}",
                    start, received_ms, state.last, peer_mac, state.frames, state.calls
                );
                check(stack)?;
                let mut state = readiness.0.get();
                state.armed = false;
                readiness.0.set(state);
                return Ok(());
            }
            stack.wait(1);
            check(stack)?;
        }
        Err("preparation poll work bound".into())
    })();
    if result.is_err() {
        readiness.refuse("preparation refused");
    }
    result
}

fn selected_case<L: absd_net::Link>(
    stack: &mut Stack<L>,
    case: Case,
    unix_seconds: u64,
    observer: &Observer,
    readiness: Option<&ArpReadiness>,
) -> Result<(), String> {
    println!(
        "TLS SERVICE CASE READY id={} local_port={}",
        case.id, case.local_port
    );
    if case.grant_exhaustion {
        exhaustion(stack, case)?;
        println!(
            "TLS CHILD DONE id={} class=Exhausted actor=granting-service",
            case.id
        );
        return Ok(());
    }
    if case.id == "L05" {
        prepare_l05(stack, readiness.ok_or("L05 preparation missing")?)?;
    }
    let start = absd_runtime::boot_millis();
    let expiry = start
        .checked_add(case.grant_lifetime_ms)
        .ok_or("grant expiry overflow")?;
    let service_deadline = expiry
        .checked_add(2000)
        .ok_or("service deadline overflow")?;
    let session = stream::Session::grant(
        stack,
        stream::Grant {
            local_port: case.local_port,
            peer: Address {
                ip: [10, 0, 2, 2],
                port: 4443,
            },
            connect_timeout_ms: case.connect_timeout_ms,
            lifetime_ms: case.grant_lifetime_ms,
        },
    )
    .map_err(|error| format!("grant {error:?}"))?;
    println!(
        "TLS SERVICE GRANT id={} before_ms={} constructed_ms={} owner_expiry_ms={}",
        case.id,
        start,
        absd_runtime::boot_millis(),
        expiry
    );
    let mut channel = stream::channel::Channel::new(session);
    let mut child = match spawn_child(case, unix_seconds, expiry) {
        Ok(child) => child,
        Err(error) => {
            channel.revoke(stack);
            stack.poll();
            return Err(error);
        }
    };
    let mut report_printed = false;
    let result = (|| {
        let mut last = start;
        let mut interrupt_observed = None;
        let mut owner_expired = false;
        let mut zero_window_established = case.id != "L04/full-rx";
        loop {
            let checked = absd_runtime::boot_millis();
            if checked < last || checked >= service_deadline {
                return Err("service clock or deadline".into());
            }
            if !owner_expired && checked >= expiry {
                owner_expired = true;
                channel.revoke(stack);
                drop(child.pipe.take());
                println!(
                    "TLS SERVICE GRANT EXPIRED id={} observed_ms={} owner_expiry_ms={}",
                    case.id, checked, expiry
                );
            }
            stack.poll();
            if let Some(pipe) = &mut child.pipe {
                if !channel.poll(stack, pipe) {
                    drop(child.pipe.take());
                }
            }
            child.read_report()?;
            let now = absd_runtime::boot_millis();
            if now < last || now >= service_deadline {
                return Err("service clock or deadline".into());
            }
            last = now;
            if let Some(marker) = case.interrupt_after {
                if interrupt_observed.is_none()
                    && child
                        .result
                        .windows(marker.len())
                        .any(|bytes| bytes == marker.as_bytes())
                {
                    interrupt_observed = Some(now);
                    println!(
                        "TLS CHILD INTERRUPT OBSERVED id={} observed_ms={} delay_ms={} marker={:?}",
                        case.id, now, case.interrupt_delay_ms, marker
                    );
                }
                if !child.killed
                    && interrupt_observed
                        .is_some_and(|observed| now - observed >= case.interrupt_delay_ms)
                {
                    println!(
                        "TLS CHILD INTERRUPT REQUEST id={} requested_ms={} observed_ms={}",
                        case.id,
                        now,
                        interrupt_observed.unwrap()
                    );
                    if case.id == "L04/full-rx" {
                        let observed = window_snapshot(case, "pre_interrupt", observer);
                        let at = absd_runtime::boot_millis();
                        zero_window_established = observed.latest_window == Some(0)
                            && observed.zero_events > 0
                            && !observed.clock_refused
                            && !observed.counters_saturated
                            && observed.last_zero_ms.is_some_and(|time| time <= at)
                            && observed.last_ack_ms.is_some_and(|time| time <= at);
                    }
                    // Do not poll the stream channel between this snapshot
                    // and kill. The observation is an advertised TCP window,
                    // not a numeric measurement of the receive queue.
                    let returned = child.kill()?;
                    println!(
                        "TLS CHILD INTERRUPT RETURN id={} result={} end_ms={} zero_window_established={}",
                        case.id,
                        returned,
                        absd_runtime::boot_millis(),
                        zero_window_established
                    );
                }
            }
            if let Some(record) = child.wait(1)? {
                channel.revoke(stack);
                drop(child.pipe.take());
                // The child no longer owns a diagnostic writer. Drain its
                // bounded remaining bytes, then close our reader explicitly.
                while child.read_report()? != 0 {}
                println!(
                    "TLS CHILD EXIT id={} kind={} status={} killed={}",
                    case.id, record[0], record[1], child.killed
                );
                let text = String::from_utf8_lossy(&child.result);
                print!(
                    "TLS CONSUMER id={} begin\n{}TLS CONSUMER id={} end\n",
                    case.id, text, case.id
                );
                report_printed = true;
                if case.interrupt_after.is_some() {
                    if !child.killed || record[0] != 3 {
                        return Err("interruption outcome".into());
                    }
                    if !zero_window_established {
                        println!(
                            "TLS CHILD DONE id={} class=NOT_ESTABLISHED actor=consumer",
                            case.id
                        );
                        return Err("advertised zero-window branch not established".into());
                    }
                } else if record[0] != 1 || record[1] != 0 {
                    return Err("consumer did not produce a normal report".into());
                }
                if case.interrupt_after.is_none() {
                    let prefix = format!("TLS RESULT case={} ", case.id);
                    if text
                        .lines()
                        .filter(|line| line.starts_with(&prefix))
                        .count()
                        != 1
                    {
                        return Err("missing or duplicate typed result".into());
                    }
                }
                println!(
                    "TLS CHILD DONE id={} class={} actor=consumer",
                    case.id,
                    if child.killed {
                        "Interrupted"
                    } else {
                        "Reported"
                    }
                );
                return Ok(());
            }
            stack.wait(1);
        }
    })();
    if !report_printed {
        print!(
            "TLS CONSUMER PARTIAL id={} begin\n{}TLS CONSUMER PARTIAL id={} end\n",
            case.id,
            String::from_utf8_lossy(&child.result),
            case.id
        );
    }
    channel.revoke(stack);
    drop(child);
    // Give an already accepted native CLOSE one bounded polling interval.
    // Retirement below fences this whole isolated service generation; it
    // does not claim a peer acknowledgment or natural TIME_WAIT expiration.
    let until = absd_runtime::boot_millis()
        .checked_add(100)
        .ok_or("cleanup overflow")?;
    while absd_runtime::boot_millis() < until {
        stack.poll();
        stack.wait(1);
    }
    let observed = window_snapshot(case, "final", observer);
    if case.id == "L03"
        && (observed.zero_events == 0
            || observed.reopen_events == 0
            || observed.clock_refused
            || observed.counters_saturated)
    {
        return Err("advertised zero/reopened window branch not established".into());
    }
    result
}

fn await_empty_input_eof() -> Result<(), String> {
    let start = absd_runtime::boot_millis();
    let deadline = start
        .checked_add(1000)
        .ok_or("startup stdin deadline overflow")?;
    let input = absd_runtime::standard_stream_handles().0;
    if input == 0 {
        return Err("missing startup stdin".into());
    }
    let before = absd_runtime::boot_millis();
    if before < start || before >= deadline {
        return Err("startup stdin clock or deadline".into());
    }
    let mut byte = [0u8; 1];
    let result = absd_runtime::read_within(input, &mut byte, deadline - before);
    let after = absd_runtime::boot_millis();
    if after < before || after >= deadline {
        return Err("startup stdin clock or deadline".into());
    }
    match result {
        Ok(0) => Ok(()),
        Ok(_) => Err("unexpected startup stdin data".into()),
        Err(error) => Err(format!("startup stdin EOF read {error}")),
    }
}

fn run() -> Result<(), String> {
    absd_runtime::link_anchor();
    let id = option_env!("ABSD_TLS_CASE").unwrap_or("P01");
    let case = fixture_cases::find(id).ok_or("unknown selected case")?;
    let time = option_env!("ABSD_TLS_UNIX_SECONDS").ok_or("missing fixture time selector")?;
    if time.is_empty() || time.len() > 20 || !time.bytes().all(|byte| byte.is_ascii_digit()) {
        return Err("fixture time selector".into());
    }
    let unix_seconds = time.parse::<u64>().map_err(|_| "fixture time overflow")?;
    await_empty_input_eof()?;
    println!(
        "TLS SERVICE SELECTOR case={} unix_seconds={} local_port={} expected_body={} grant_lifetime_ms={} connect_timeout_ms={}",
        case.id,
        unix_seconds,
        case.local_port,
        case.expected_body,
        case.grant_lifetime_ms,
        case.connect_timeout_ms
    );
    let before = census("before")?;
    let link = NicLink::from_startup().map_err(|error| format!("NIC {error:?}"))?;
    let readiness = (case.id == "L05").then(ArpReadiness::default);
    let link = PreparationLink {
        inner: link,
        readiness: readiness.clone(),
    };
    let (link, observer) = ObservedLink::new(link, case.local_port);
    let mut stack =
        Stack::open(link, Config::qemu_user()).map_err(|error| format!("stack {error:?}"))?;
    let result = selected_case(
        &mut stack,
        case,
        unix_seconds,
        &observer,
        readiness.as_ref(),
    );
    let closing = stack.socket_count();
    stack.stream_fence();
    stack.datagram_fence();
    stack.poll();
    let remaining = stack.socket_count();
    println!(
        "TLS SERVICE RETIRE id={} sockets_before_fence={} sockets_after_fence={}",
        case.id, closing, remaining
    );
    drop(stack);
    drop(observer);
    drop(readiness);
    absd_runtime::heap_free_pooled_pages();
    let after = census("after")?;
    println!(
        "TLS SERVICE DONE id={} sockets={} processes_before={} processes_after={} handles_before={} handles_after={} pipes_before={} pipes_after={} cells_before={} cells_after={}",
        case.id,
        remaining,
        before.processes,
        after.processes,
        before.handles,
        after.handles,
        before.pipes,
        after.pipes,
        before.cells,
        after.cells
    );
    if remaining != 0
        || before.processes != after.processes
        || before.handles != after.handles
        || before.pipes != after.pipes
        || before.cells != after.cells
    {
        return Err("resource or authority retained".into());
    }
    result
}

fn main() -> std::process::ExitCode {
    match run() {
        Ok(()) => std::process::ExitCode::SUCCESS,
        Err(error) => {
            println!("TLS SERVICE ERROR error={error:?}");
            std::process::ExitCode::from(1)
        }
    }
}
