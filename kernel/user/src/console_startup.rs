//! Startup publication precedes interactive presentation. This gate owns no
//! recovery authority and never changes the host readiness/witness grammar.
use absd_abi::program::ServedReadyProbe;

pub struct Gate {
    lines: [Marker; 2],
    ready: bool,
    active: bool,
}
impl Gate {
    pub const fn new() -> Self {
        Self {
            lines: [Marker::new(), Marker::new()],
            ready: false,
            active: false,
        }
    }
    /// Preserve every byte until handoff, including marker suffixes. Each
    /// stream has its own parser; interleaved partial lines cannot combine.
    pub fn capture_worker(&mut self, stream: usize, bytes: &[u8]) -> bool {
        if self.active {
            return false;
        }
        let Some(line) = self.lines.get_mut(stream) else {
            return false;
        };
        self.ready |= line.push(bytes);
        true
    }
    /// Called only after a later supervision pass drains FSD's startup
    /// streams to idle at complete-line boundaries.
    pub fn drained(&mut self, fsd_idle: bool) {
        self.active |= self.ready && fsd_idle;
    }
    pub fn active(&self) -> bool {
        self.active
    }
    pub fn ready(&self) -> bool {
        self.ready
    }
}

struct Marker {
    bytes: [u8; 96],
    length: usize,
    overflow: bool,
}
impl Marker {
    const fn new() -> Self {
        Self {
            bytes: [0; 96],
            length: 0,
            overflow: false,
        }
    }
    fn push(&mut self, bytes: &[u8]) -> bool {
        let mut ready = false;
        for &byte in bytes {
            if byte == b'\n' {
                ready |= !self.overflow
                    && ServedReadyProbe::presentation_line(&self.bytes[..self.length]);
                self.length = 0;
                self.overflow = false;
            } else if self.length < self.bytes.len() && !self.overflow {
                self.bytes[self.length] = byte;
                self.length += 1;
            } else {
                self.overflow = true;
            }
        }
        ready
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    const LISTENER: &[u8] = b"SSH LISTENING port=22 authorized_keys=1 preauth_per_source=2\n";
    #[test]
    fn complete_startup_is_captured_before_a_later_idle_handoff() {
        for split in 1..=LISTENER.len() {
            let mut gate = Gate::new();
            assert!(!gate.ready());
            gate.drained(true);
            assert!(!gate.active());
            for bytes in LISTENER.chunks(split) {
                assert!(gate.capture_worker(1, bytes));
            }
            assert!(gate.ready());
            assert!(!gate.active());
            gate.drained(false);
            assert!(!gate.active());
            gate.drained(true);
            assert!(gate.active());
            assert!(!gate.capture_worker(0, b"runtime\n"));
        }
    }
    #[test]
    fn presentation_is_separate_from_enrollment_and_recovery_readiness() {
        let local = b"LOCAL READY boot=0123456789abcdef0123456789abcdef enrolled=0\n";
        let mut gate = Gate::new();
        for byte in local {
            assert!(gate.capture_worker(1, &[*byte]));
        }
        gate.drained(true);
        assert!(gate.active());
        assert!(!ServedReadyProbe::new().push(local));
    }
    #[test]
    fn fragments_from_distinct_streams_cannot_authorize_presentation() {
        let mut gate = Gate::new();
        gate.capture_worker(0, &LISTENER[..20]);
        gate.capture_worker(1, &LISTENER[20..]);
        gate.drained(true);
        assert!(!gate.active());
        gate.capture_worker(0, b"\n");
        gate.capture_worker(0, &[b'x'; 97]);
        gate.capture_worker(0, LISTENER);
        gate.drained(true);
        assert!(!gate.active());
        gate.capture_worker(0, LISTENER);
        gate.drained(true);
        assert!(gate.active());
    }
}
