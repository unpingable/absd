//! Exclusive physical-input router: the maintenance prefix never reaches shells.
#[derive(Default)]
pub struct Router {
    pub maintenance: bool,
    escape: bool,
}
#[derive(Debug, Eq, PartialEq)]
pub enum Action {
    None,
    Forward([u8; 2], usize),
    Kernel,
    Resume,
}
impl Router {
    pub fn input(&mut self, byte: u8) -> Action {
        if self.escape {
            self.escape = false;
            return match byte {
                b'k' => {
                    self.maintenance = true;
                    Action::Kernel
                }
                b'r' => {
                    self.maintenance = false;
                    Action::Resume
                }
                _ if self.maintenance => Action::None,
                _ => Action::Forward([0x1d, byte], 2),
            };
        }
        if byte == 0x1d {
            self.escape = true;
            Action::None
        } else if self.maintenance {
            Action::None
        } else {
            Action::Forward([byte, 0], 1)
        }
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn maintenance_never_delivers_input_to_a_retained_shell() {
        let mut r = Router::default();
        assert_eq!(r.input(0x1d), Action::None);
        assert_eq!(r.input(b'k'), Action::Kernel);
        for &b in b"password\n\x03\x04" {
            assert_eq!(r.input(b), Action::None);
        }
        assert_eq!(r.input(0x1d), Action::None);
        assert_eq!(r.input(b'r'), Action::Resume);
        assert_eq!(r.input(b'a'), Action::Forward([b'a', 0], 1));
    }
    #[test]
    fn session_switch_prefix_is_whole_across_batches() {
        let mut r = Router::default();
        assert_eq!(r.input(0x1d), Action::None);
        assert_eq!(r.input(b'2'), Action::Forward([0x1d, b'2'], 2));
        assert_eq!(r.input(b'x'), Action::Forward([b'x', 0], 1));
    }
}

/// Bounded physical-input relay; overflow cancels rather than splicing a command.
pub struct Relay {
    /// Matches the upstream Console FIFO and worker input queue headroom.
    pub pending: [u8; 8192],
    pub count: usize,
    pub dropped: u64,
    pub discard_line: bool,
}
impl Relay {
    pub const fn new() -> Self {
        Self {
            pending: [0; 8192],
            count: 0,
            dropped: 0,
            discard_line: false,
        }
    }
    pub fn enqueue(&mut self, bytes: &[u8]) {
        if self.discard_line {
            self.dropped = self.dropped.saturating_add(bytes.len() as u64);
            if bytes.iter().any(|b| *b == b'\r' || *b == b'\n') {
                self.discard_line = false;
            }
            return;
        }
        if self.count + bytes.len() <= self.pending.len() {
            self.pending[self.count..self.count + bytes.len()].copy_from_slice(bytes);
            self.count += bytes.len();
        } else {
            // Fail closed on relay overflow: never splice a dropped suffix into
            // a command. Cancel the edited line and discard until its newline.
            self.dropped = self
                .dropped
                .saturating_add((self.count + bytes.len()) as u64);
            self.pending.fill(0);
            self.pending[0] = 3;
            self.count = 1;
            self.discard_line = !bytes.iter().any(|b| *b == b'\r' || *b == b'\n');
        }
    }
}

#[cfg(test)]
mod relay_tests {
    use super::Relay;
    #[test]
    fn overflow_cancels_partial_input_and_drops_suffix_until_newline() {
        let mut relay = Relay::new();
        relay.enqueue(&[b'x'; 8192]);
        relay.enqueue(b"dangerous suffix");
        assert_eq!(&relay.pending[..relay.count], &[3]);
        assert!(relay.discard_line);
        relay.enqueue(b"command\n");
        assert!(!relay.discard_line);
        assert_eq!(&relay.pending[..relay.count], &[3]);
        relay.enqueue(b"safe\n");
        assert_eq!(&relay.pending[..relay.count], b"\x03safe\n");
        assert!(relay.dropped > 8192);
    }
}
