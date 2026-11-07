#![feature(restricted_std)]
//! Genuine-router MTU consumer using delegated kernel pipes and two children.
#[path = "../tcp_mtu_delegated_pipe.rs"]
mod observation;
use absd_net::{
    Config, Link, LinkReading, NicLink, Stack,
    datagram::{
        self,
        channel::{KernelPipe, Pipe},
    },
    stream,
};
use absd_runtime::{
    RIGHT_READ, RIGHT_WRITE,
    process::{SPAWN_NO_SPAWN, spawn_image_raw},
};
use std::{cell::RefCell, rc::Rc};

const REPORT_MAX: usize = 1_048_576;
fn sys(number: u64, a: u64, b: u64, c: u64) -> i64 {
    let value: i64;
    unsafe {
        core::arch::asm!("int 0x80",inlateout("rax")number=>value,in("rdi")a,in("rsi")b,in("rdx")c,options(nostack,preserves_flags));
    }
    value
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
    let raw = sys(16, 0, 0, 0);
    if raw < 0 {
        return Err(format!("pipe {raw}"));
    }
    let both = Handle(raw as u64);
    let reader = Handle(
        absd_runtime::duplicate(both.0, RIGHT_READ).map_err(|e| format!("read handle {e}"))?,
    );
    let writer = Handle(
        absd_runtime::duplicate(both.0, RIGHT_WRITE).map_err(|e| format!("write handle {e}"))?,
    );
    Ok((reader, writer))
}
struct Clock {
    last: u64,
    whole: u64,
}
impl Clock {
    fn now(&mut self, until: u64) -> Result<u64, String> {
        let now = absd_runtime::boot_millis();
        if until > self.whole || now < self.last || now >= until {
            return Err("original owner clock/deadline".into());
        }
        self.last = now;
        Ok(now)
    }
}
struct Frame {
    tx: bool,
    ordinal: usize,
    phase: &'static str,
    at: u64,
    bytes: Vec<u8>,
}
struct Trace {
    rows: Vec<Frame>,
    counts: [usize; 2],
    phase: &'static str,
    flushed: usize,
}
impl Trace {
    fn room(&self, tx: bool, n: usize) -> Result<(), i64> {
        if n > absd_net::FRAME_MAX || self.counts[usize::from(!tx)] >= 256 {
            Err(-5)
        } else {
            Ok(())
        }
    }
    fn record(&mut self, tx: bool, bytes: &[u8], at: u64) {
        let count = &mut self.counts[usize::from(!tx)];
        *count += 1;
        self.rows.push(Frame {
            tx,
            ordinal: *count,
            phase: self.phase,
            at,
            bytes: bytes.to_vec(),
        });
    }
    fn emit(&mut self) {
        for f in &self.rows[self.flushed..] {
            println!(
                "TCP MTU DELEGATED FRAME v=1 direction={} ordinal={} phase={} at_ms={} bytes={} hex={}",
                if f.tx { "tx" } else { "rx" },
                f.ordinal,
                f.phase,
                f.at,
                f.bytes.len(),
                observation::hex(&f.bytes)
            );
        }
        self.flushed = self.rows.len();
        println!(
            "TCP MTU DELEGATED FRAME_SEAL v=1 phase={} records={} tx={} rx={}",
            self.phase,
            self.rows.len(),
            self.counts[0],
            self.counts[1]
        );
    }
}
struct ReceiptLink {
    inner: NicLink,
    trace: Rc<RefCell<Trace>>,
}
impl Link for ReceiptLink {
    fn mac(&self) -> [u8; 6] {
        self.inner.mac()
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
    fn send(&mut self, bytes: &[u8]) -> Result<(), i64> {
        self.trace.borrow().room(true, bytes.len())?;
        self.inner.send(bytes)?;
        self.trace
            .borrow_mut()
            .record(true, bytes, self.inner.now_ms());
        Ok(())
    }
    fn receive(
        &mut self,
        bytes: &mut [u8; absd_net::FRAME_MAX],
        timeout: u64,
    ) -> Result<Option<usize>, i64> {
        self.trace.borrow().room(false, 0)?;
        let result = self.inner.receive(bytes, timeout)?;
        if let Some(n) = result {
            if n > bytes.len() {
                return Err(-5);
            }
            self.trace
                .borrow_mut()
                .record(false, &bytes[..n], self.inner.now_ms());
        }
        Ok(result)
    }
}
struct Child {
    process: u64,
    pipe: Option<observation::Observed<KernelPipe>>,
    result_reader: Handle,
    result: Vec<u8>,
    result_eof: Option<u64>,
}
impl Child {
    fn failure_drain(&mut self) {
        // This is failure custody, not a successful extension of any grant.
        // Stop only our child, retain its actual terminal diagnostics, and
        // leave an explicit missing-reap/EOF observation if cleanup refuses.
        let process = self.process;
        let killed = if process != 0 {
            sys(20, process, 0, 0)
        } else {
            0
        };
        let mut last = absd_runtime::boot_millis();
        let end = last.saturating_add(1000);
        while self.process != 0 || self.result_eof.is_none() {
            let now = absd_runtime::boot_millis();
            if now < last || now >= end {
                break;
            }
            last = now;
            if self.read_result().is_err() {
                break;
            }
            if self.process != 0 && self.wait().is_err() {
                break;
            }
        }
        eprintln!(
            "TCP MTU DELEGATED FAILURE_DRAIN v=1 process={process} kill_return={killed} process_reaped={} result_eof={} result_bytes={}",
            u8::from(self.process == 0),
            u8::from(self.result_eof.is_some()),
            self.result.len()
        );
    }
    fn wait(&mut self) -> Result<Option<[u64; 4]>, String> {
        if self.process == 0 {
            return Err("already reaped child".into());
        }
        let mut record = [0; 4];
        let status = sys(6, self.process, record.as_mut_ptr() as u64, 1);
        if status == -110 {
            return Ok(None);
        }
        if status < 0 {
            return Err(format!("wait {status}"));
        }
        self.process = 0;
        Ok(Some(record))
    }
    fn read_result(&mut self) -> Result<(), String> {
        if self.result_eof.is_some() {
            return Ok(());
        }
        let mut bytes = [0; 1024];
        match absd_runtime::read_within(self.result_reader.0, &mut bytes, 1) {
            Ok(0) => self.result_eof = Some(absd_runtime::boot_millis()),
            Ok(n) => {
                if self
                    .result
                    .len()
                    .checked_add(n)
                    .is_none_or(|n| n > REPORT_MAX)
                {
                    return Err("child result bound".into());
                }
                self.result.extend_from_slice(&bytes[..n]);
            }
            Err(-110 | -11) => {}
            Err(e) => return Err(format!("result read {e}")),
        }
        Ok(())
    }
}
impl Drop for Child {
    fn drop(&mut self) {
        drop(self.pipe.take());
        if self.process != 0 {
            let process = self.process;
            let killed = sys(20, process, 0, 0);
            let mut record = [0u64; 4];
            let waited = sys(6, process, record.as_mut_ptr() as u64, 1000);
            eprintln!(
                "TCP MTU DELEGATED FAILURE_CLEANUP v=1 process={process} kill_return={killed} wait_return={waited} wait_kind={} wait_status={}",
                record[0], record[1]
            );
            if waited < 0 {
                let _ = absd_runtime::close(process);
            }
            self.process = 0;
        }
    }
}
fn spawn(child: usize, ledger: Rc<RefCell<observation::Ledger>>) -> Result<Child, String> {
    let (child_in, mut parent_out) = pipe()?;
    let (mut parent_in, child_out) = pipe()?;
    let (result_reader, result_writer) = pipe()?;
    let (startup_reader, startup_writer) = pipe()?;
    let copies = [
        [startup_reader.0, RIGHT_READ, 0],
        [child_in.0, RIGHT_READ, 0],
        [child_out.0, RIGHT_WRITE, 0],
        [result_writer.0, RIGHT_WRITE, 0],
        [result_writer.0, RIGHT_WRITE, 1],
    ];
    let arg = child.to_string();
    let mut record = [0; absd_broker::MAX_STARTUP];
    let length = absd_broker::encode_startup(
        &[
            (absd_broker::role::STDIN, 1),
            (absd_broker::role::STDOUT, 2),
            (absd_broker::role::STDERR, 3),
        ],
        [arg.as_bytes()],
        [],
        b"/",
        b"tcp-mtu-delegated-client",
        copies.len(),
        &mut record,
    )
    .map_err(|e| format!("startup {e:?}"))?;
    let image = include_bytes!(env!("ABSD_TCP_MTU_DELEGATED_CHILD_ELF"));
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
        process: process as u64,
        pipe: Some(observation::Observed::new(
            KernelPipe {
                request_reader: parent_in.take(),
                reply_writer: parent_out.take(),
            },
            ledger,
            true,
        )),
        result_reader,
        result: Vec::new(),
        result_eof: None,
    };
    drop((startup_reader, child_in, child_out, result_writer));
    let written = absd_runtime::write_within(startup_writer.0, &record[..length], 1000)
        .map_err(|e| format!("startup write {e}"))?;
    if written != length {
        return Err("partial broker startup write".into());
    }
    Ok(child)
}
fn census(label: &str) -> Result<absd_runtime::ResourceCensus, String> {
    let c = absd_runtime::resource_census().map_err(|e| format!("census {e}"))?;
    println!(
        "TCP MTU DELEGATED CENSUS v=1 label={label} processes={} handles={} pipes={} cells={} frames={}",
        c.processes, c.handles, c.pipes, c.cells, c.frames
    );
    Ok(c)
}
fn same_objects(a: &absd_runtime::ResourceCensus, b: &absd_runtime::ResourceCensus) -> bool {
    (a.processes, a.handles, a.pipes, a.cells) == (b.processes, b.handles, b.pipes, b.cells)
}
fn phase(
    stack: &mut Stack<ReceiptLink>,
    trace: &Rc<RefCell<Trace>>,
    clock: &mut Clock,
    child_id: usize,
    until: u64,
) -> Result<(), String> {
    let phase = if child_id == 1 { "refusal" } else { "positive" };
    trace.borrow_mut().phase = phase;
    let before = census(if child_id == 1 {
        "refusal-before"
    } else {
        "positive-before"
    })?;
    let at = clock.now(until)?;
    let peer = datagram::Address {
        ip: [198, 51, 100, 2],
        port: if child_id == 1 { 42100 } else { 42101 },
    };
    let local = if child_id == 1 { 7100 } else { 7101 };
    let lifetime = until - at;
    let mut channel = stream::channel::Channel::grant_mtu_refusal(
        stack,
        stream::Grant {
            local_port: local,
            peer,
            connect_timeout_ms: 4000,
            lifetime_ms: lifetime,
        },
    )
    .map_err(|e| format!("grant {e:?}"))?;
    println!(
        "TCP MTU DELEGATED GRANT v=1 child={child_id} phase={phase} local_port={local} peer_port={} at_ms={at} until_ms={until} lifetime_ms={lifetime}",
        peer.port
    );
    let ledger = Rc::new(RefCell::new(observation::Ledger::new()));
    let mut child = match spawn(child_id, ledger.clone()) {
        Ok(child) => child,
        Err(e) => {
            channel.revoke(stack);
            return Err(e);
        }
    };
    let child_handle = child.process;
    println!(
        "TCP MTU DELEGATED SPAWN v=1 child={child_id} phase={phase} process_handle={child_handle} at_ms={} no_spawn=1 nic_copies=0 protocol_handles=2 diagnostic_handles=2",
        clock.now(until)?
    );
    let outcome: Result<(), String> = (|| {
        let mut boot = [0u8; 20];
        boot[..5].copy_from_slice(b"MTUD\x01");
        boot[5] = child_id as u8;
        boot[6..10].copy_from_slice(&peer.ip);
        boot[10..12].copy_from_slice(&peer.port.to_be_bytes());
        boot[12..20].copy_from_slice(&until.to_be_bytes());
        let mut offset = 0;
        while offset < boot.len() {
            clock.now(until)?;
            match child
                .pipe
                .as_mut()
                .ok_or("missing owner pipe")?
                .write(&boot[offset..])
                .map_err(|e| format!("bootstrap write {e}"))?
            {
                Some(n) if n > 0 => offset += n,
                None => {}
                _ => return Err("bootstrap write EOF".into()),
            }
            clock.now(until)?;
        }
        println!(
            "TCP MTU DELEGATED BOOTSTRAP v=1 child={child_id} phase={phase} at_ms={} bytes=20 hex={}",
            clock.now(until)?,
            observation::hex(&boot)
        );
        let record = loop {
            clock.now(until)?;
            if let Some(pipe) = child.pipe.as_mut() {
                channel.poll(stack, pipe);
            }
            clock.now(until)?;
            if !channel.live() && ledger.borrow().request_eof.is_none() {
                return Err("channel retired without actual protocol EOF".into());
            }
            stack.poll();
            clock.now(until)?;
            child.read_result()?;
            clock.now(until)?;
            let waited = child.wait()?;
            clock.now(until)?;
            if let Some(record) = waited {
                break record;
            }
            stack.wait(1);
        };
        let reaped = clock.now(until)?;
        while child.result_eof.is_none() {
            clock.now(until)?;
            child.read_result()?;
            clock.now(until)?;
        }
        while channel.live() {
            clock.now(until)?;
            channel.poll(stack, child.pipe.as_mut().ok_or("missing EOF pipe")?);
            clock.now(until)?;
        }
        let eof = ledger
            .borrow()
            .request_eof
            .ok_or("true protocol EOF absent")?;
        if record[0] != 1 || record[1] != 0 || !ledger.borrow().good() {
            return Err(format!("normal child/ledger outcome {record:?}"));
        }
        let text = std::str::from_utf8(&child.result).map_err(|_| "child report UTF8")?;
        for kind in if child_id == 1 {
            &[
                "CHILD_BEGIN",
                "CHILD_CONNECTED",
                "CHILD_QUEUED",
                "CHILD_REFUSED",
                "CHILD_FENCED",
                "CHILD_DONE",
            ][..]
        } else {
            &[
                "CHILD_BEGIN",
                "CHILD_CONNECTED",
                "CHILD_QUEUED",
                "CHILD_OBSERVED",
                "CHILD_EOF",
                "CHILD_DONE",
            ][..]
        } {
            let prefix = format!("TCP MTU DELEGATED {kind} v=1 child={child_id} phase={phase} ");
            if text
                .lines()
                .filter(|line| line.starts_with(&prefix))
                .count()
                != 1
            {
                return Err(format!("child report {kind}"));
            }
        }
        if text.contains("CHILD_FAIL") {
            return Err("child failure marker".into());
        }
        println!(
            "TCP MTU DELEGATED REAP v=1 child={child_id} phase={phase} reaped_ms={reaped} at_ms={} kind={} status={} request_eof_ms={eof} result_eof_ms={} channel_live={} eof_revoked=1",
            clock.now(until)?,
            record[0],
            record[1],
            child.result_eof.ok_or("true result EOF absent")?,
            u8::from(channel.live())
        );
        Ok(())
    })();
    let live_before = channel.live();
    channel.revoke(stack);
    let explicit = absd_runtime::boot_millis();
    drop(child.pipe.take());
    if outcome.is_err() {
        child.failure_drain();
    }
    // Print bounded diagnostics on failure too. Source order records
    // observation times; buffered publication is not cross-process ordering.
    print!("{}", String::from_utf8_lossy(&child.result));
    ledger.borrow().emit("owner", child_id, phase);
    let process_reaped = child.process == 0;
    let result_eof = child.result_eof;
    drop(child); // A failure still owns and reaps only this exact child.
    stack.poll();
    trace.borrow_mut().emit();
    let after = census(if child_id == 1 {
        "refusal-after"
    } else {
        "positive-after"
    })?;
    if outcome.is_ok() {
        clock.now(until)?;
        println!(
            "TCP MTU DELEGATED RETIRED v=1 child={child_id} phase={phase} explicit_revoke_ms={explicit} channel_live_before_explicit={} channel_live={} process_handle_live=0 protocol_handles=0 result_handles=0 sockets={} objects_restored={}",
            u8::from(live_before),
            u8::from(channel.live()),
            stack.socket_count(),
            u8::from(same_objects(&before, &after))
        );
    } else {
        eprintln!(
            "TCP MTU DELEGATED PHASE_FAIL v=1 child={child_id} phase={phase} process_reaped={} result_eof={} channel_live={} sockets={}",
            u8::from(process_reaped),
            u8::from(result_eof.is_some()),
            u8::from(channel.live()),
            stack.socket_count()
        );
    }
    outcome?;
    clock.now(until)?;
    if stack.socket_count() != 0 || !same_objects(&before, &after) {
        return Err("phase object/socket retirement".into());
    }
    Ok(())
}
fn run(trace: Rc<RefCell<Trace>>) -> Result<(), String> {
    absd_runtime::link_anchor();
    let start = absd_runtime::boot_millis();
    let whole = start.checked_add(30000).ok_or("whole overflow")?;
    let refusal = start.checked_add(12000).ok_or("refusal overflow")?;
    let mut clock = Clock { last: start, whole };
    let nic = NicLink::from_startup().map_err(|e| format!("NIC {e:?}"))?;
    let mut stack = Stack::open(
        ReceiptLink {
            inner: nic,
            trace: trace.clone(),
        },
        Config {
            address: [192, 0, 2, 100].into(),
            prefix_len: 24,
            gateway: Some([192, 0, 2, 1].into()),
            rx_buffer: 2048,
            tx_buffer: 2048,
        },
    )
    .map_err(|e| format!("stack {e:?}"))?;
    println!(
        "TCP MTU DELEGATED BEGIN v=1 start_ms={start} until_ms={whole} refusal_until_ms={refusal} guest=192.0.2.100 router=192.0.2.1 peer=198.51.100.2"
    );
    phase(&mut stack, &trace, &mut clock, 1, refusal)?;
    let now = clock.now(whole)?;
    let positive = now
        .checked_add(10000)
        .filter(|until| *until <= whole)
        .ok_or("insufficient original budget for fresh positive grant")?;
    println!(
        "TCP MTU DELEGATED POSITIVE v=1 at_ms={now} until_ms={positive} child=2 fresh_grant=1 old_child_retired=1"
    );
    phase(&mut stack, &trace, &mut clock, 2, positive)?;
    println!(
        "TCP MTU DELEGATED DONE v=1 at_ms={} children=2 sockets=0 negative_bytes=1024 positive_bytes=64",
        clock.now(whole)?
    );
    Ok(())
}
fn main() {
    let trace = Rc::new(RefCell::new(Trace {
        rows: Vec::new(),
        counts: [0, 0],
        phase: "refusal",
        flushed: 0,
    }));
    let result = run(trace.clone());
    if let Err(error) = result {
        trace.borrow_mut().emit();
        eprintln!("TCP MTU DELEGATED FAIL v=1 error={error:?}");
        std::process::exit(1);
    }
}
