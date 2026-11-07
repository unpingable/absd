//! Init is the single-threaded compositor and sole holder of display authority.
#[allow(
    dead_code,
    reason = "Producer and consumer use complementary parts of this private wire protocol."
)]
#[path = "mwm_successor.rs"]
mod transport;
use absd_user::{
    Child, Console, Error, LineBuffer, Outcome, Pipe, RIGHT_READ, RIGHT_WRITE, SPAWN_NO_SPAWN,
    SpawnHandleCopy, close, duplicate, kill, program, spawn_many_copy, syscall3, time,
    wait_timeout, yield_now,
};
use core::fmt::Write;
use transport::*;
const WAIT: u64 = 30_000;
static mut CONSUMERS: [[Consumer; 2]; 2] = [
    [Consumer::new_const(), Consumer::new_const()],
    [Consumer::new_const(), Consumer::new_const()],
];

fn line(console: Console, args: core::fmt::Arguments<'_>) -> Result<(), &'static str> {
    let mut text = LineBuffer::new();
    text.write_fmt(args).map_err(|_| "line overflow")?;
    console.write_all(text.as_bytes()).map_err(|_| "console")
}
struct Peer {
    reader: Pipe,
    child: Child,
    bytes: [u8; 256],
    used: usize,
    length: usize,
    last_progress: u64,
    read_size: usize,
}
// Split one pipe without leaving extra readers or writers that would hide EOF.
fn channel() -> Result<(Pipe, Pipe), &'static str> {
    let pipe = Pipe::create().map_err(|_| "pipe")?;
    let reader = duplicate(pipe.raw(), RIGHT_READ);
    let writer = duplicate(pipe.raw(), RIGHT_WRITE);
    let closed = close(pipe.raw());
    match (reader, writer, closed) {
        (Ok(r), Ok(w), Ok(())) => Ok((Pipe::from_raw(r), Pipe::from_raw(w))),
        (r, w, _) => {
            if let Ok(r) = r {
                let _ = close(r);
            }
            if let Ok(w) = w {
                let _ = close(w);
            }
            Err("pipe rights")
        }
    }
}
impl Peer {
    fn spawn(
        console: Console,
        session: u64,
        generation: u64,
        count: u64,
        delay: u64,
        crash: bool,
    ) -> Result<Self, &'static str> {
        let (reader, writer) = channel()?;
        let (config, control) = match channel() {
            Ok(pair) => pair,
            Err(error) => {
                let _ = close(reader.raw());
                let _ = close(writer.raw());
                return Err(error);
            }
        };
        let spawned = spawn_many_copy(
            program::EXTERNAL_WORKLOAD | SPAWN_NO_SPAWN,
            &[
                SpawnHandleCopy::new(writer.raw(), RIGHT_WRITE),
                SpawnHandleCopy::new(config.raw(), RIGHT_READ),
                SpawnHandleCopy::console(console.raw(), RIGHT_WRITE),
            ],
        );
        let closed = close(writer.raw()).and(close(config.raw()));
        let child = match spawned {
            Ok(child) => child,
            Err(_) => {
                let _ = close(reader.raw());
                let _ = close(control.raw());
                return Err("producer spawn");
            }
        };
        let peer = Self {
            reader,
            child,
            bytes: [0; 256],
            used: 0,
            length: 0,
            last_progress: time(),
            read_size: if delay == 0 { 256 } else { 63 },
        };
        let configured = [session, generation, count, delay, u64::from(crash)]
            .iter()
            .try_for_each(|word| control.write_all(&word.to_le_bytes()));
        let config_closed = close(control.raw());
        if closed.is_err() || configured.is_err() || config_closed.is_err() {
            let _ = peer.retire(console, session);
            return Err("producer configuration");
        }
        Ok(peer)
    }
    fn retire(self, console: Console, session: u64) -> Result<Outcome, &'static str> {
        let closed = close(self.reader.raw());
        let mut killed = false;
        let outcome = match wait_timeout(Some(self.child), WAIT) {
            Ok(outcome) => Ok(outcome),
            Err(Error::Timeout) => {
                killed = true;
                kill(self.child).map_err(|_| "producer kill")?;
                wait_timeout(Some(self.child), WAIT)
            }
            Err(error) => Err(error),
        };
        line(
            console,
            format_args!(
                "MWM SLICE3 RETIRE session={} closed={} killed={} outcome={:?}\n",
                session,
                closed.is_ok(),
                killed,
                outcome
            ),
        )?;
        if closed.is_ok() && !killed {
            outcome.map_err(|_| "producer wait")
        } else {
            Err("producer retirement")
        }
    }
}
impl Stream for Peer {
    // Sole reader: writers can add bytes or close, preserving observed readiness.
    fn poll(&mut self, c: &mut Consumer) -> Result<(), End> {
        if self.used == self.length {
            let info = self.reader.info().map_err(|_| End::Io)?;
            let Some(limit) = ready_read(
                info.available as usize,
                info.writers as usize,
                self.read_size,
            ) else {
                return if time().saturating_sub(self.last_progress) >= WAIT {
                    Err(End::Timeout)
                } else {
                    Ok(())
                };
            };
            self.length = self
                .reader
                .read_once(&mut self.bytes[..limit])
                .map_err(|_| End::Io)?;
            self.used = 0;
            self.last_progress = time();
            if self.length == 0 {
                c.end(End::UnexpectedEof);
                return Ok(());
            }
        }
        self.used += c
            .bytes(&self.bytes[self.used..self.length])
            .map_err(|_| End::Malformed)?;
        Ok(())
    }
}
struct Source(Option<Peer>);
impl Stream for Source {
    fn poll(&mut self, c: &mut Consumer) -> Result<(), End> {
        self.0.as_mut().ok_or(End::Io)?.poll(c)
    }
}
struct Display {
    handle: u64,
    generation: u64,
    operation: u64,
    x: u32,
}
impl Sink for Display {
    fn select(&mut self, client: usize) {
        self.x = [16, 400][client];
    }
    fn strip(&mut self, _: u64, row: usize, pixels: &[u8]) -> Result<(), SinkError> {
        self.operation = self.operation.checked_add(1).ok_or(SinkError)?;
        let mut r = [0u8; 48];
        r[..8].copy_from_slice(&self.operation.to_le_bytes());
        r[8..12].copy_from_slice(&self.x.to_le_bytes());
        r[12..16].copy_from_slice(&(16 + row as u32).to_le_bytes());
        r[16..20].copy_from_slice(&(WIDTH as u32).to_le_bytes());
        r[20..24].copy_from_slice(&(ROWS as u32).to_le_bytes());
        r[24..28].copy_from_slice(&((WIDTH * 4) as u32).to_le_bytes());
        r[28..32].copy_from_slice(&(1u32 | (32 << 8)).to_le_bytes());
        r[32..40].copy_from_slice(&(pixels.len() as u64).to_le_bytes());
        r[40..48].copy_from_slice(&self.generation.to_le_bytes());
        if unsafe {
            syscall3(
                0x7fd2,
                self.handle,
                r.as_ptr() as u64,
                pixels.as_ptr() as u64,
            )
        } == 0
        {
            Ok(())
        } else {
            Err(SinkError)
        }
    }
    fn mask(&mut self) -> Result<(), SinkError> {
        self.operation = self.operation.checked_add(1).ok_or(SinkError)?;
        if unsafe { syscall3(0x7fd3, self.handle, self.operation, self.generation) } == 0 {
            Ok(())
        } else {
            Err(SinkError)
        }
    }
}
fn ledger(console: Console, client: usize, c: &Consumer) -> Result<(), &'static str> {
    let l = c.ledger;
    line(
        console,
        format_args!(
            "MWM SLICE3 LEDGER client={} accepted={} presented={} failed={} unknown={} discarded={} revoked={} refused_revoked={} queued={} balanced={} end={:?} last={:?}\n",
            client,
            l.accepted,
            l.presented,
            l.failed,
            l.unknown,
            l.discarded,
            l.revoked,
            l.refused_revoked,
            c.queued(),
            c.balanced(),
            c.end_reason(),
            c.last_presented()
        ),
    )?;
    if !c.balanced() {
        return Err("ledger imbalance");
    }
    Ok(())
}
fn checkpoint(console: Console, name: &str, clients: &[Consumer; 2]) -> Result<(), &'static str> {
    for (i, c) in clients.iter().enumerate() {
        ledger(console, i, c)?;
    }
    line(console, format_args!("MWM SLICE3 PIXELS READY {}\n", name))?;
    absd_user::mwm_protocol::wait_ack(console, WAIT)
}
pub fn run(console: Console) -> Result<(), &'static str> {
    let digest = env!("ABSD_MWM_SUCCESSOR_SHA");
    if digest.len() != 64 {
        return Err("missing ELF identity");
    }
    line(
        console,
        format_args!("MWM SLICE3 BOOT elf_sha256={} tick={}\n", digest, time()),
    )?;
    let handle = unsafe { syscall3(0x7fd0, 0, 0, 0) };
    if handle <= 0 {
        return Err("display open");
    }
    let handle = handle as u64;
    let result = (|| {
        let mut info = [0; 48];
        if unsafe { syscall3(0x7fd1, handle, info.as_mut_ptr() as u64, 0) } != 0 {
            return Err("display info");
        }
        let info = absd_user::mwm_protocol::parse_info(&info)?;
        if info.generation != 1 || info.high_water != 0 {
            return Err("fresh display");
        }
        let pairs = unsafe { &mut *core::ptr::addr_of_mut!(CONSUMERS) };
        let mut display = Display {
            handle,
            generation: info.generation,
            operation: 0,
            x: 16,
        };
        for (phase, clients) in pairs.iter_mut().enumerate() {
            let sessions = if phase == 0 { [17, 29] } else { [41, 53] };
            for i in 0..2 {
                clients[i].grant(sessions[i], 1).map_err(|_| "grant")?;
            }
            let a = Peer::spawn(console, sessions[0], 1, 24, 0, phase == 0)?;
            let b = match Peer::spawn(console, sessions[1], 1, 8, 150, false) {
                Ok(b) => b,
                Err(error) => {
                    let _ = a.retire(console, sessions[0]);
                    return Err(error);
                }
            };
            let mut peers = [Source(Some(a)), Source(Some(b))];
            let mut pump = Pump::new();
            let scenario = (|| {
                // These are observation boundaries only; neither producer receives
                // frame requests or acknowledgements. Pipe backpressure bounds them.
                let mut live = false;
                let mut masked = false;
                let deadline = time() + WAIT;
                loop {
                    if time() >= deadline {
                        return Err("scenario deadline");
                    }
                    // A retired source is never polled; a small adapter allows its
                    // actual child to be reaped immediately while B keeps running.
                    pump.turn(clients, &mut peers, &mut display)
                        .map_err(|_| "pump display")?;
                    if !live && clients.iter().all(|c| c.last_presented().is_some()) {
                        live = true;
                        checkpoint(
                            console,
                            if phase == 0 {
                                "crash-live"
                            } else {
                                "revoke-live"
                            },
                            clients,
                        )?;
                        if phase == 1 {
                            pump.revoke(0, clients, &mut display)
                                .map_err(|_| "revoke/recompose")?;
                        }
                    }
                    if pump.retired[0] && !masked {
                        if !live {
                            return Err("A retired before live checkpoint");
                        }
                        masked = true;
                        line(
                            console,
                            format_args!(
                                "MWM SLICE3 SERVICE phase={} visits_a={} visits_b={} b_at_retirement={}\n",
                                phase, pump.visits[0], pump.visits[1], clients[1].ledger.presented
                            ),
                        )?;
                        let outcome = peers[0]
                            .0
                            .take()
                            .ok_or("missing A")?
                            .retire(console, sessions[0])?;
                        let expected = if phase == 0 {
                            matches!(outcome, Outcome::Faulted { vector: 6, .. })
                        } else {
                            matches!(outcome, Outcome::Exited(91) | Outcome::Exited(0))
                        };
                        if !expected {
                            return Err("unexpected A outcome");
                        }
                        checkpoint(
                            console,
                            if phase == 0 {
                                "crash-masked"
                            } else {
                                "revoke-masked"
                            },
                            clients,
                        )?;
                    }
                    if clients[1].end_reason() == Some(End::Orderly) && clients[1].queued() == 0 {
                        if !masked || clients[1].ledger.presented != 8 {
                            return Err("B continuation");
                        }
                        let outcome = peers[1]
                            .0
                            .take()
                            .ok_or("missing B")?
                            .retire(console, sessions[1])?;
                        if outcome != Outcome::Exited(0) {
                            return Err("B retirement");
                        }
                        line(console, format_args!("MWM SLICE3 FAIR phase={} visits_a={} visits_b={} presented_a={} presented_b={}
",
                            phase, pump.visits[0], pump.visits[1], clients[0].ledger.presented, clients[1].ledger.presented))?;
                        checkpoint(
                            console,
                            if phase == 0 {
                                "crash-done"
                            } else {
                                "revoke-done"
                            },
                            clients,
                        )?;
                        break;
                    }
                    yield_now();
                }
                Ok(())
            })();
            // Always close/reap both actual peers; keep the first scenario failure.
            let mut cleanup = Ok(());
            for (i, peer) in peers.into_iter().enumerate() {
                if let Some(peer) = peer.0 {
                    clients[i].end(End::Io);
                    if peer.retire(console, sessions[i]).is_err() {
                        cleanup = Err("cleanup");
                    }
                }
                ledger(console, i, &clients[i])?;
            }
            scenario?;
            cleanup?;
            if clients
                .iter()
                .any(|c| !c.balanced() || c.queued() != 0 || c.mask_required())
            {
                return Err("unresolved responsibility");
            }
            // Clear the prior pair before installing fresh lifetime objects.
            pump.revoke(1, clients, &mut display)
                .map_err(|_| "pair mask")?;
        }
        console
            .write_str("MWM SLICE3 OK\n")
            .map_err(|_| "success marker")
    })();
    let closed = close(handle);
    result?;
    closed.map_err(|_| "display close")
}
