#![feature(restricted_std)]
//! One selected QUIC fixture per boot, using existing spawn and datagram roles.

use absd_native_quic_fixture::{
    PEER, fixture_cases,
    fixture_family::{Family, IPV6_LOCAL, IPV6_PEER},
    service_lifecycle,
};
use absd_net::datagram::{
    self as d,
    channel::{KernelPipe, Pipe},
};
use absd_net::ipv6 as v6;
use absd_net::{Config, Link, NicLink, Stack};
use absd_runtime::{
    RIGHT_READ, RIGHT_WRITE,
    process::{SPAWN_NO_SPAWN, spawn_image_raw},
};
use fixture_cases::Case;

const REPORT_LIMIT: usize = 65_536;

// One selected channel holds the real endpoint. Family selection never creates
// authority; grant construction stays in this parent holding the NIC.
enum OwnedChannel {
    V4(d::channel::Channel),
    V6(v6::channel::Channel),
}
impl service_lifecycle::LiveGrant for OwnedChannel {
    fn live(&self) -> bool {
        match self {
            Self::V4(channel) => channel.live(),
            Self::V6(channel) => channel.live(),
        }
    }
}
impl OwnedChannel {
    fn grant<L: absd_net::Link>(
        stack: &mut Stack<L>,
        family: Family,
        local_port: u16,
    ) -> Result<Self, String> {
        match family {
            Family::Ipv4 => d::channel::Channel::grant(
                stack,
                d::Grant {
                    local_port,
                    peer: PEER,
                },
            )
            .map(Self::V4)
            .map_err(|error| format!("grant {error:?}")),
            Family::Ipv6 => v6::channel::Channel::grant(
                stack,
                v6::Grant {
                    local_port,
                    peer: IPV6_PEER,
                },
            )
            .map(Self::V6)
            .map_err(|error| format!("grant {error:?}")),
        }
    }
    fn revoke<L: absd_net::Link>(&mut self, stack: &mut Stack<L>) {
        match self {
            Self::V4(channel) => channel.revoke(stack),
            Self::V6(channel) => channel.revoke(stack),
        }
    }
    fn poll<L: absd_net::Link, P: Pipe>(&mut self, stack: &mut Stack<L>, pipe: &mut P) -> bool {
        match self {
            Self::V4(channel) => channel.poll(stack, pipe),
            Self::V6(channel) => channel.poll(stack, pipe),
        }
    }
}

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

// Q20 acknowledges one complete successful SEND reply to Channel without
// delivering it to the child. Session::request has already queued the datagram.
// This is a local completion-loss fixture, never a retry of that operation.
struct FixturePipe {
    inner: KernelPipe,
    suppress: bool,
    suppressed: bool,
    case_id: &'static str,
    family: Family,
    delivered: [u8; d::MAX_MESSAGE + 2],
    used: usize,
    rx_ordinal: u64,
    request: [u8; d::MAX_MESSAGE + 2],
    request_used: usize,
    send_requests: u64,
    sends_after_owner_expiry: u64,
    owner_expiry_ms: u64,
}
impl FixturePipe {
    fn observe_request(&mut self, mut bytes: &[u8]) -> Result<(), i64> {
        while !bytes.is_empty() {
            let wanted = if self.request_used < 2 {
                2
            } else {
                2 + u16::from_be_bytes([self.request[0], self.request[1]]) as usize
            };
            if wanted > self.request.len()
                || (self.request_used >= 2 && wanted < self.family.header() + 2)
            {
                return Err(-22);
            }
            let count = bytes.len().min(wanted - self.request_used);
            self.request[self.request_used..self.request_used + count]
                .copy_from_slice(&bytes[..count]);
            self.request_used += count;
            bytes = &bytes[count..];
            if self.request_used == wanted && wanted != 2 {
                if wanted < self.family.header() + 2 {
                    return Err(-22);
                }
                let body = &self.request[2..wanted];
                if body[0] != self.family.version()
                    || body[3] != self.family.wire_family()
                    || body[1] > d::CLOSE
                {
                    return Err(-22);
                }
                if body[1] == d::SEND {
                    let length = self.family.length(body).ok_or(-22i64)?;
                    if body.len() != self.family.header() + length || self.send_requests >= 4096 {
                        return Err(-22);
                    }
                    let now = self.now_ms();
                    self.send_requests += 1;
                    if now >= self.owner_expiry_ms {
                        self.sends_after_owner_expiry += 1;
                        return Err(-110);
                    }
                    let (peer, scope, port) = self.family.peer_text(body).ok_or(-22i64)?;
                    let extra = if self.family == Family::Ipv6 {
                        format!(" family=6 scope={scope}")
                    } else {
                        String::new()
                    };
                    println!(
                        "QUIC FIXTURE SEND case={} ordinal={} at_ms={} bytes={} peer_ip={} peer_port={}{}",
                        self.case_id, self.send_requests, now, length, peer, port, extra
                    );
                }
                self.request_used = 0;
            }
        }
        Ok(())
    }
    fn observe_delivery(&mut self, mut bytes: &[u8]) -> Result<(), i64> {
        while !bytes.is_empty() {
            let wanted = if self.used < 2 {
                2
            } else {
                2 + u16::from_be_bytes([self.delivered[0], self.delivered[1]]) as usize
            };
            if wanted > self.delivered.len()
                || (self.used >= 2 && wanted < self.family.header() + 2)
            {
                return Err(-22);
            }
            let count = bytes.len().min(wanted - self.used);
            self.delivered[self.used..self.used + count].copy_from_slice(&bytes[..count]);
            self.used += count;
            bytes = &bytes[count..];
            if self.used == wanted && wanted != 2 {
                if wanted < self.family.header() + 2 {
                    return Err(-22);
                }
                let body = &self.delivered[2..wanted];
                if body[0] != self.family.version() || body[3] != self.family.wire_family() {
                    return Err(-22);
                }
                if body[1] == d::RECEIVE && body[2] == 0 {
                    let length = self.family.length(body).ok_or(-22i64)?;
                    let max_datagram = match self.family {
                        Family::Ipv4 => d::MAX_DATAGRAM,
                        Family::Ipv6 => v6::MAX_DATAGRAM,
                    };
                    if body.len() != self.family.header() + length
                        || length > max_datagram
                        || self.rx_ordinal >= 256
                    {
                        return Err(-22);
                    }
                    self.rx_ordinal += 1;
                    let hash =
                        ring::digest::digest(&ring::digest::SHA256, &body[self.family.header()..]);
                    let mut text = String::with_capacity(64);
                    use std::fmt::Write;
                    for byte in hash.as_ref() {
                        let _ = write!(text, "{byte:02x}");
                    }
                    let (peer, scope, port) = self.family.peer_text(body).ok_or(-22i64)?;
                    let extra = if self.family == Family::Ipv6 {
                        format!(" family=6 scope={scope}")
                    } else {
                        String::new()
                    };
                    println!(
                        "QUIC FIXTURE RX case={} ordinal={} at_ms={} bytes={} peer_ip={} peer_port={} sha256={}{}",
                        self.case_id,
                        self.rx_ordinal,
                        self.now_ms(),
                        length,
                        peer,
                        port,
                        text,
                        extra
                    );
                }
                self.used = 0;
            }
        }
        Ok(())
    }
}
impl Pipe for FixturePipe {
    fn now_ms(&self) -> u64 {
        self.inner.now_ms()
    }
    fn read(&mut self, bytes: &mut [u8]) -> Result<Option<usize>, i64> {
        if self.now_ms() >= self.owner_expiry_ms {
            return Err(-110);
        }
        let result = self.inner.read(bytes)?;
        if self.now_ms() >= self.owner_expiry_ms {
            return Err(-110);
        }
        if let Some(count) = result {
            if count > bytes.len() {
                return Err(-5);
            }
            self.observe_request(&bytes[..count])?;
        }
        Ok(result)
    }
    fn write(&mut self, bytes: &[u8]) -> Result<Option<usize>, i64> {
        if self.suppress
            && !self.suppressed
            && bytes.len() == 14
            && bytes[..6] == [0, 12, d::VERSION, d::SEND, 0, 0]
            && bytes[6..] == [0; 8]
        {
            self.suppressed = true;
            println!(
                "QUIC FIXTURE SUPPRESSED_REPLY case={} at_ms={} opcode={} status=0 framed_bytes={}",
                self.case_id,
                self.now_ms(),
                d::SEND,
                bytes.len()
            );
            return Ok(Some(bytes.len()));
        }
        let result = self.inner.write(bytes)?;
        if let Some(count) = result {
            if count > bytes.len() {
                return Err(-5);
            }
            self.observe_delivery(&bytes[..count])?;
        }
        Ok(result)
    }
}

impl Drop for FixturePipe {
    fn drop(&mut self) {
        println!(
            "QUIC FIXTURE NATIVE_COUNTS case={} at_ms={} send_requests={} receive_delivered={} sends_after_owner_expiry={} partial_request_bytes={} partial_reply_bytes={}",
            self.case_id,
            self.now_ms(),
            self.send_requests,
            self.rx_ordinal,
            self.sends_after_owner_expiry,
            self.request_used,
            self.used
        );
    }
}

struct Child {
    process: Option<u64>,
    pipe: Option<FixturePipe>,
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
                    "QUIC CLEANUP process={} kill={:?} wait={:?}",
                    process, kill, wait
                );
                let _ = absd_runtime::close(process);
                self.process = None;
            }
        }
    }
}

fn spawn_child(
    case: Case,
    family: Family,
    unix_seconds: u64,
    grant_expiry_ms: u64,
) -> Result<Child, String> {
    let image = include_bytes!(env!("ABSD_QUIC_CLIENT_ELF"));
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
    // The runtime supplies argv[0] from the startup record's program name.
    let args: [&[u8]; 6] = [
        b"--case",
        case.id.as_bytes(),
        b"--unix-time",
        time.as_bytes(),
        b"--grant-expiry",
        expiry.as_bytes(),
    ];
    let mut startup = [0; absd_broker::MAX_STARTUP];
    let roles = if case.missing_output {
        vec![
            (absd_broker::role::STDIN, 1),
            (absd_broker::role::STDERR, 3),
        ]
    } else {
        vec![
            (absd_broker::role::STDIN, 1),
            (absd_broker::role::STDOUT, 2),
            (absd_broker::role::STDERR, 3),
        ]
    };
    let length = absd_broker::encode_startup(
        &roles,
        args,
        [],
        b"/",
        b"quic-echo",
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
        pipe: Some(FixturePipe {
            inner: KernelPipe {
                request_reader: parent_in.take(),
                reply_writer: parent_out.take(),
            },
            suppress: case.suppress_reply,
            suppressed: false,
            case_id: case.id,
            family,
            delivered: [0; d::MAX_MESSAGE + 2],
            used: 0,
            rx_ordinal: 0,
            request: [0; d::MAX_MESSAGE + 2],
            request_used: 0,
            send_requests: 0,
            sends_after_owner_expiry: 0,
            owner_expiry_ms: grant_expiry_ms,
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
        "QUIC SERVICE RESOURCES label={} processes={} handles={} pipes={} cells={} frames={} allocated_frames={} free_frames={} allocation_limit={:?} heap_pages={}",
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

fn selected_case<L: absd_net::Link>(
    stack: &mut Stack<L>,
    case: Case,
    family: Family,
    unix_seconds: u64,
) -> Result<(), String> {
    let start = absd_runtime::boot_millis();
    let expiry = start
        .checked_add(case.grant_lifetime_ms)
        .ok_or("grant expiry overflow")?;
    let service_deadline = expiry
        .checked_add(2000)
        .ok_or("service deadline overflow")?;
    let mut channel = OwnedChannel::grant(stack, family, case.local_port)?;
    println!(
        "QUIC SERVICE GRANT case={} before_ms={} constructed_ms={} owner_expiry_ms={} local_port={} peer_port={}",
        case.id,
        start,
        absd_runtime::boot_millis(),
        expiry,
        case.local_port,
        match family {
            Family::Ipv4 => PEER.port,
            Family::Ipv6 => IPV6_PEER.port,
        }
    );
    let mut child = match spawn_child(case, family, unix_seconds, expiry) {
        Ok(child) => child,
        Err(error) => {
            channel.revoke(stack);
            return Err(error);
        }
    };
    let mut report_printed = false;
    let result = (|| {
        let mut last = start;
        let mut interrupt_observed = None;
        let mut owner_expired = false;
        let mut queue_held = case.queue_control;
        loop {
            let checked = absd_runtime::boot_millis();
            if checked < last || checked >= service_deadline {
                return Err("service clock or deadline".into());
            }
            // Owner expiry revokes the exact existing grant before subsequent
            // dispatch. This observed-clock policy does not retract prior wire effects.
            if !owner_expired && checked >= expiry {
                owner_expired = true;
                channel.revoke(stack);
                drop(child.pipe.take());
                println!(
                    "QUIC SERVICE GRANT EXPIRED case={} observed_ms={} owner_expiry_ms={}",
                    case.id, checked, expiry
                );
            }
            service_lifecycle::poll_if_granted(stack, &channel, queue_held);
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
            if queue_held {
                let marker = format!("QUIC PHASE case={} phase=QueueFull", case.id);
                if child
                    .result
                    .windows(marker.len())
                    .any(|bytes| bytes == marker.as_bytes())
                {
                    queue_held = false;
                    println!(
                        "QUIC FIXTURE QUEUE RELEASE case={} at_ms={} trigger=real_Initial_Exhausted",
                        case.id, now
                    );
                }
            }
            if let Some(phase) = case.interrupt_phase {
                let marker = format!("QUIC PHASE case={} phase={}", case.id, phase);
                if interrupt_observed.is_none()
                    && child
                        .result
                        .windows(marker.len())
                        .any(|bytes| bytes == marker.as_bytes())
                {
                    interrupt_observed = Some(now);
                    println!(
                        "QUIC CHILD INTERRUPT OBSERVED case={} phase={} observed_ms={} delay_ms={}",
                        case.id, phase, now, case.interrupt_delay_ms
                    );
                }
                if !child.killed
                    && interrupt_observed
                        .is_some_and(|observed| now - observed >= case.interrupt_delay_ms)
                {
                    println!(
                        "QUIC CHILD INTERRUPT REQUEST case={} requested_ms={} observed_ms={}",
                        case.id,
                        now,
                        interrupt_observed.unwrap()
                    );
                    let returned = child.kill()?;
                    println!(
                        "QUIC CHILD INTERRUPT RETURN case={} result={} end_ms={}",
                        case.id,
                        returned,
                        absd_runtime::boot_millis()
                    );
                }
            }
            if let Some(record) = child.wait(1)? {
                channel.revoke(stack);
                drop(child.pipe.take());
                while child.read_report()? != 0 {}
                println!(
                    "QUIC CHILD EXIT case={} kind={} status={} killed={}",
                    case.id, record[0], record[1], child.killed
                );
                let text = String::from_utf8_lossy(&child.result);
                print!(
                    "QUIC CONSUMER case={} begin\n{}QUIC CONSUMER case={} end\n",
                    case.id, text, case.id
                );
                report_printed = true;
                if case.interrupt_phase.is_some() {
                    if !child.killed || record[0] != 3 {
                        return Err("interruption outcome".into());
                    }
                } else {
                    if record[0] != 1 || record[1] != 0 {
                        return Err("consumer did not produce a normal report".into());
                    }
                    let prefix = format!("QUIC RESULT case={} ", case.id);
                    if text
                        .lines()
                        .filter(|line| line.starts_with(&prefix))
                        .count()
                        != 1
                    {
                        return Err("missing or duplicate typed result".into());
                    }
                }
                return Ok(());
            }
            // Holding Q19 must not call Stack::poll or Stack::wait: both network
            // input/egress and queue drain remain with the exact parent owner.
            if !service_lifecycle::wait_if_granted(stack, &channel, queue_held, 1) {
                absd_runtime::sleep_ticks(1);
            }
        }
    })();
    if !report_printed {
        print!(
            "QUIC CONSUMER PARTIAL case={} begin\n{}QUIC CONSUMER PARTIAL case={} end\n",
            case.id,
            String::from_utf8_lossy(&child.result),
            case.id
        );
    }
    channel.revoke(stack);
    drop(child);
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
    let id = option_env!("ABSD_QUIC_CASE").unwrap_or("Q01");
    let case = fixture_cases::find(id).ok_or("unknown selected case")?;
    let family = Family::selected().map_err(str::to_owned)?;
    family.check_case(case.id).map_err(str::to_owned)?;
    let time = option_env!("ABSD_QUIC_UNIX_SECONDS").ok_or("missing fixture time selector")?;
    if time.is_empty() || time.len() > 20 || !time.bytes().all(|byte| byte.is_ascii_digit()) {
        return Err("fixture time selector".into());
    }
    let unix_seconds = time.parse::<u64>().map_err(|_| "fixture time overflow")?;
    await_empty_input_eof()?;
    println!(
        "QUIC SERVICE SELECTOR case={} unix_seconds={} local_port={} grant_lifetime_ms={}",
        case.id, unix_seconds, case.local_port, case.grant_lifetime_ms
    );
    let before = census("before")?;
    let link = NicLink::from_startup().map_err(|error| format!("NIC {error:?}"))?;
    if family == Family::Ipv6 {
        let reading = link.read().ok_or("NIC reading unavailable")?;
        if reading.disabled || !reading.link_up {
            return Err("NIC link unavailable".into());
        }
        // The same pre-grant settling interval as the current IPv6 TLS fixture.
        // No Stack/network poll occurs here and no child/grant clock has begun.
        let nic_ready = absd_runtime::boot_millis();
        let ready_after = nic_ready.checked_add(1100).ok_or("NIC setup overflow")?;
        let setup_deadline = nic_ready.checked_add(3000).ok_or("NIC setup overflow")?;
        let mut previous = nic_ready;
        loop {
            let observed = absd_runtime::boot_millis();
            if observed < previous || observed >= setup_deadline {
                return Err("NIC setup clock or deadline".into());
            }
            previous = observed;
            if observed >= ready_after {
                println!(
                    "QUIC IPV6 RX SETUP case={} nic_ready_ms={} ready_ms={} delta_ms={} continuous_vm_required=1",
                    case.id,
                    nic_ready,
                    observed,
                    observed - nic_ready
                );
                break;
            }
            absd_runtime::sleep_ticks(10);
        }
    }
    let mut stack =
        Stack::open(link, Config::qemu_user()).map_err(|error| format!("stack {error:?}"))?;
    if family == Family::Ipv6 {
        stack
            .configure_ipv6(v6::Config {
                address: IPV6_LOCAL,
                prefix_len: 64,
                scope: 1,
            })
            .map_err(|error| format!("IPv6 owner configuration {error:?}"))?;
        println!(
            "QUIC SERVICE FAMILY case={} family=6 scope=1 local_ip=fd00:ab5d::15 peer_ip=fd00:ab5d::2 peer_port=4443",
            case.id
        );
    }
    let result = selected_case(&mut stack, case, family, unix_seconds);
    let closing = stack.socket_count();
    service_lifecycle::fence(&mut stack);
    let remaining = stack.socket_count();
    println!(
        "QUIC SERVICE RETIRE case={} sockets_before_fence={} sockets_after_fence={}",
        case.id, closing, remaining
    );
    drop(stack);
    absd_runtime::heap_free_pooled_pages();
    let after = census("after")?;
    println!(
        "QUIC SERVICE DONE case={} sockets={} processes_before={} processes_after={} handles_before={} handles_after={} pipes_before={} pipes_after={} cells_before={} cells_after={}",
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
            println!("QUIC SERVICE ERROR error={error:?}");
            std::process::ExitCode::from(1)
        }
    }
}
