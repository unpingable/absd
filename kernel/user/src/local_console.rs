//! Init's bounded physical terminal relay. No filesystem or service RPCs.
#[path = "console_text.rs"]
mod console_text;
#[path = "console_router.rs"]
mod router;
use absd_user::kernel_log as log;
use absd_user::{Console, Error, Pipe, RIGHT_READ, RIGHT_WRITE, close, duplicate};
use core::fmt::Write;
use core::sync::atomic::{AtomicBool, Ordering};
#[path = "console_startup.rs"]
mod startup;
static STARTUP_CAPTURE_CLOSED: AtomicBool = AtomicBool::new(false);
#[path = "console_snapshot.rs"]
mod console_snapshot;
use console_snapshot::Snapshot;
use router::{Action, Relay, Router};

pub fn enabled() -> bool {
    matches!(option_env!("ABSD_LOCAL_CONSOLE"), Some("1"))
}

pub fn startup_capture_closed() -> bool {
    STARTUP_CAPTURE_CLOSED.load(Ordering::Relaxed)
}

pub fn claim(console: Console) -> Result<(), &'static str> {
    if enabled() {
        absd_user::set_console_presentation(console, true)
            .map_err(|_| "managed physical presentation refused")?;
    }
    Ok(())
}

/// The UI has ended; allow intentional terminal shutdown/reset diagnostics.
pub fn release(console: Console) {
    if enabled() && absd_user::set_console_presentation(console, false).is_err() {
        let _ = console.write_str("init: physical presentation release refused\n");
    }
}

pub struct Terminal {
    reader: Pipe,
    writer: u64,
    router: Router,
    relay: Relay,
    snapshot: Snapshot,
    startup: startup::Gate,
}
impl Terminal {
    pub fn new() -> Result<Self, &'static str> {
        // Framing cannot resume after intentionally omitted runtime bytes.
        if startup_capture_closed() {
            return Err("local startup capture already closed");
        }
        let both = Pipe::create().map_err(|_| "local terminal pipe")?;
        let reader = duplicate(both.raw(), RIGHT_READ).map_err(|_| "local terminal reader")?;
        let writer = duplicate(both.raw(), RIGHT_WRITE).map_err(|_| "local terminal writer")?;
        close(both.raw()).map_err(|_| "local terminal split")?;
        Ok(Self {
            reader: Pipe::from_raw(reader),
            writer,
            router: Router::default(),
            relay: Relay::new(),
            snapshot: Snapshot::new(),
            startup: startup::Gate::new(),
        })
    }
    pub fn writer(&self) -> u64 {
        self.writer
    }
    pub fn spawned(&mut self) {
        let _ = close(self.writer);
        self.writer = 0;
    }
    pub fn capture_worker(&mut self, stream: usize, bytes: &[u8]) -> bool {
        self.startup.capture_worker(stream, bytes)
    }
    pub fn startup_ready(&self) -> bool {
        self.startup.ready()
    }
    pub fn startup_drained(&mut self, fsd_idle: bool) {
        self.startup.drained(fsd_idle);
        if self.startup.active() {
            STARTUP_CAPTURE_CLOSED.store(true, Ordering::Relaxed);
        }
    }
    pub fn step(&mut self, console: Console, input: Pipe) {
        let mut bytes = [0u8; 128];
        if let Ok(n) = console.read_timeout(&mut bytes, 1) {
            for &b in &bytes[..n] {
                match self.router.input(b) {
                    Action::None => {}
                    Action::Forward(bytes, n) if self.startup.active() => {
                        self.relay.enqueue(&bytes[..n]);
                    }
                    Action::Forward(..) => {}
                    Action::Kernel => {
                        // The read-only escape stays available after captured
                        // publication is retired; it never revives that stream.
                        let _ = super::console_lines::boundary(console);
                        // No queued future input may cross the maintenance boundary.
                        self.relay.pending.fill(0);
                        self.relay.count = 0;
                        self.snapshot.restart();
                        let _ = console.write_str("\nABSD kernel maintenance (read-only; no filesystem/network required)\nCtrl-] r returns to local login. Ctrl-] k restarts snapshot.\n");
                    }
                    Action::Resume => {
                        if self.startup.active() {
                            self.relay.enqueue(&[0x1d, b'r']);
                        }
                    }
                }
            }
        }
        if self.relay.count > 0 {
            match input.write_timeout(&self.relay.pending[..self.relay.count], 1) {
                Ok(n) => {
                    self.relay.pending.copy_within(n..self.relay.count, 0);
                    self.relay.count -= n;
                    self.relay.pending[self.relay.count..].fill(0);
                }
                Err(Error::Timeout) => {}
                Err(_) => {
                    self.relay.pending.fill(0);
                    self.relay.count = 0;
                }
            }
        }
        if self.relay.dropped > 0 {
            let mut line = absd_user::LineBuffer::new();
            let _ = writeln!(
                line,
                "\n[local input overrun: {} bytes dropped]",
                self.relay.dropped
            );
            let _ = console.write_all(line.as_bytes());
            self.relay.dropped = 0;
        }
        let mut output = [0u8; 256];
        if self.startup.active()
            && let Ok(n) = self.reader.read_timeout(&mut output, 1)
            && !self.router.maintenance
        {
            let _ = console.write_all(&output[..n]);
        }
        if self.router.maintenance {
            let _ = super::console_lines::boundary(console);
            kernel_snapshot(console, &mut self.snapshot);
        }
    }
}
impl Drop for Terminal {
    fn drop(&mut self) {
        self.relay.pending.fill(0);
        let _ = close(self.reader.raw());
        if self.writer != 0 {
            let _ = close(self.writer);
        }
    }
}

/// Read only through init's inherited Diagnostics grant. Display writes bypass
/// the retained log, so rendering cannot recursively generate its own input.
fn kernel_snapshot(console: Console, snapshot: &mut Snapshot) {
    snapshot.step(
        |cursor| log::read_decoded(0, cursor),
        |bytes| {
            let _ = console.write_all(bytes);
        },
    );
}

/// Before readiness or after recovery-budget exhaustion, retain this visible
/// route. This grants no shell, stop or restart authority.
pub fn hold(console: Console, reason: &str) -> ! {
    let _ = super::console_lines::boundary(console);
    if let Err(error) = claim(console) {
        let _ = console.write_str(error);
        let _ = console.write_str("\n");
    }
    let _ = console.write_str("\nABSD LOCAL MAINTENANCE: service failure: ");
    let _ = console.write_str(reason);
    let _=console.write_str("\nRead-only kernel diagnostics remain available. Services were stopped; this is not in-place recovery.\nExternal operator reboot is required to restart services. Ctrl-] k repeats diagnostics.\n");
    let mut snapshot = Snapshot::new();
    let mut router = Router::default();
    router.maintenance = true;
    loop {
        let mut bytes = [0u8; 128];
        if let Ok(n) = console.read_timeout(&mut bytes, 20) {
            for &b in &bytes[..n] {
                if router.input(b) == Action::Kernel {
                    snapshot.restart();
                }
            }
        }
        kernel_snapshot(console, &mut snapshot);
    }
}
