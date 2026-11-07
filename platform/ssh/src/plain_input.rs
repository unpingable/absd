//! Constant-memory cancellation fence for managed plain source input.
pub const CAPABILITY: &str = "plain-discard-v1";

#[derive(Default)]
pub struct Recovery {
    phase: Phase,
}

#[derive(Default, PartialEq, Eq)]
enum Phase {
    #[default]
    Open,
    Discarding,
    Cancelled,
    Ready,
}

impl Recovery {
    /// Fence writes and require a fresh explicit cancellation.
    pub fn pause(&mut self) {
        self.phase = Phase::Discarding;
    }

    pub fn paused(&self) -> bool {
        self.phase != Phase::Open
    }

    /// Report the first explicit cancellation in the discarded source.
    /// The caller drops the whole paused batch, including any Ctrl-C suffix;
    /// cancellation keeps the writer paused until pause acknowledgement and
    /// a separate rearm.
    pub fn input(&mut self, bytes: &[u8]) -> bool {
        if self.phase == Phase::Discarding && bytes.contains(&b'\x03') {
            self.phase = Phase::Cancelled;
            true
        } else {
            false
        }
    }

    /// Acknowledge the producer pause only after explicit cancellation.
    /// This permits rearm; it does not claim that the client drained its pipe.
    pub fn acknowledge_pause(&mut self) {
        if self.phase == Phase::Cancelled {
            self.phase = Phase::Ready;
        }
    }

    /// A cancellation and its later writer-pause acknowledgement arrived.
    /// The coherent client must still drain its pipe before it requests rearm.
    pub fn ready_to_rearm(&self) -> bool { self.phase == Phase::Ready }

    /// Prompt requests cannot release unacknowledged discarded source.
    pub fn rearm(&mut self) -> bool {
        if !matches!(self.phase, Phase::Open | Phase::Ready) {
            return false;
        }
        self.phase = Phase::Open;
        true
    }
}

#[cfg(test)]
mod tests {
    use super::Recovery;

    #[test]
    fn open_input_never_emits_a_recovery_cancellation() {
        let mut recovery = Recovery::default();
        assert!(!recovery.paused());
        assert!(recovery.rearm());
        assert!(!recovery.input(b"ordinary command\n\x03"));
        assert!(!recovery.paused());
    }

    #[test]
    fn early_rearm_and_syntax_boundaries_cannot_release_discarded_source() {
        let mut recovery = Recovery::default();
        recovery.pause();
        assert!(recovery.paused());
        for bytes in [
            b"".as_slice(),
            b"\n\n\r\n".as_slice(),
            b"'quote'\n",
            b"EOF\nside-effect\n",
            b"\0\xff\xc3",
        ] {
            assert!(!recovery.rearm());
            assert!(!recovery.input(bytes));
            assert!(recovery.paused());
        }
    }

    #[test]
    fn split_million_byte_source_without_cancellation_stays_fenced() {
        const CHUNK: [u8; 16_384] = [b'\n'; 16_384];
        let mut recovery = Recovery::default();
        recovery.pause();
        let mut remaining = 1_052_303;
        while remaining != 0 {
            let n = remaining.min(CHUNK.len());
            assert!(!recovery.input(&CHUNK[..n]));
            assert!(!recovery.rearm());
            remaining -= n;
        }
        assert!(recovery.paused());
        assert!(recovery.input(b"\x03"));
        assert!(
            !recovery.rearm(),
            "Ctrl-C alone must not rearm before acknowledgement"
        );
        recovery.acknowledge_pause();
        assert!(recovery.rearm());
        assert!(!recovery.paused());
    }

    #[test]
    fn cancellation_keeps_the_entire_batch_paused_and_emits_once() {
        let mut recovery = Recovery::default();
        recovery.pause();
        assert!(recovery.input(b"old-prefix\x03effectful-suffix\n\x03"));
        assert!(recovery.paused());
        for bytes in [b"\x03".as_slice(), b"suffix\n", b"\x03\x03\n"] {
            assert!(!recovery.input(bytes));
            assert!(recovery.paused());
        }
        assert!(
            !recovery.rearm(),
            "Ctrl-C alone must not rearm before acknowledgement"
        );
        recovery.acknowledge_pause();
        assert!(recovery.paused());
        assert!(!recovery.input(b"\x03another discarded suffix\n"));
        assert!(recovery.rearm());
        assert!(!recovery.paused());
        assert!(!recovery.input(b"separate fresh command\n"));
    }

    #[test]
    fn split_input_requires_the_actual_ctrl_c_byte() {
        let mut recovery = Recovery::default();
        recovery.pause();
        assert!(!recovery.input(b"prefix\xc3"));
        assert!(!recovery.input(b"\xa9\r\n"));
        assert!(!recovery.rearm());
        assert!(recovery.input(b"\x03suffix"));
        assert!(!recovery.input(b"more suffix\n"));
        assert!(!recovery.rearm());
        recovery.acknowledge_pause();
        assert!(recovery.rearm());
    }

    #[test]
    fn a_new_pause_requires_a_new_cancellation() {
        let mut recovery = Recovery::default();
        recovery.pause();
        assert!(recovery.input(b"\x03"));
        recovery.pause();
        assert!(recovery.paused());
        assert!(!recovery.rearm());
        assert!(recovery.input(b"\x03"));
        assert!(!recovery.input(b"\x03"));
        assert!(!recovery.rearm());
        recovery.acknowledge_pause();
        assert!(recovery.rearm());
    }

    #[test]
    fn acknowledgement_cannot_replace_explicit_cancellation() {
        let mut recovery = Recovery::default();
        recovery.acknowledge_pause();
        assert!(recovery.rearm());
        recovery.pause();
        recovery.acknowledge_pause();
        assert!(!recovery.rearm());
        assert!(recovery.input(b"\x03suffix"));
        assert!(!recovery.rearm(), "cancelled but not acknowledged");
        recovery.acknowledge_pause();
        recovery.acknowledge_pause();
        assert!(recovery.paused());
        assert!(!recovery.input(b"newlines\n\x03"));
        assert!(recovery.rearm());
        assert!(!recovery.paused());
    }

    #[test]
    fn a_new_pause_after_acknowledgement_requires_fresh_cancel_and_ack() {
        let mut recovery = Recovery::default();
        recovery.pause();
        assert!(recovery.input(b"\x03"));
        recovery.acknowledge_pause();
        recovery.pause();
        recovery.acknowledge_pause();
        assert!(!recovery.rearm());
        assert!(recovery.input(b"\x03"));
        assert!(!recovery.rearm());
        recovery.acknowledge_pause();
        assert!(recovery.rearm());
    }

    #[test]
    fn session_reset_does_not_carry_a_discard_or_cancellation() {
        for phase in 0..3 {
            let mut recovery = Recovery::default();
            recovery.pause();
            if phase >= 1 {
                assert!(recovery.input(b"\x03"));
            }
            if phase == 2 {
                recovery.acknowledge_pause();
            }
            recovery = Recovery::default();
            assert!(!recovery.paused());
            assert!(recovery.rearm());
            assert!(!recovery.input(b"fresh\n"));
        }
    }
}
