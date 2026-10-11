//! Versioned qualification evidence. Three explicit 64-bit words per record;
//! neither enum discriminants nor native Rust layouts are serialized.
use crate::Console;
pub struct Trace {
    console: Console,
    sequence: u64,
}
impl Trace {
    pub const fn new(console: Console) -> Self {
        Self {
            console,
            sequence: 0,
        }
    }
    pub fn record(&mut self, event: &str, words: [u64; 3]) {
        self.sequence += 1;
        self.line("SEM1", event, words);
    }
    /// Native evidence belongs to the immediately preceding semantic record.
    pub fn native(&self, event: &str, words: [u64; 3]) {
        self.line("NAT1", event, words);
    }
    fn line(&self, prefix: &str, event: &str, words: [u64; 3]) {
        assert!(
            event.len() <= 48
                && event
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b == b'_')
        );
        // Fixed fields fit in LineBuffer; one kernel write prevents interleaving.
        self.console
            .line(format_args!(
                "{prefix} {} {event} {:016x} {:016x} {:016x}\n",
                self.sequence, words[0], words[1], words[2]
            ))
            .unwrap();
    }
}
