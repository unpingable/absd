//! Bounded in-band marker and fresh-code matching. No shell grammar.
#[path = "input_record.rs"]
pub(crate) mod record;
pub use record::PREFIX as RECORD_PREFIX;

pub const BEGIN: &[u8; 6] = b"\x1b[200~";
pub const END: &[u8; 6] = b"\x1b[201~";
pub const MAX_SOURCE: usize = 1024 * 1024 - 1;
pub const MAX_QUEUED: usize = 2 * 1024 * 1024;

#[derive(Debug, Default)]
pub struct Marker { held: [u8; 6], len: usize }
pub struct Decoded { bytes: [u8; 7], len: usize, pub matched: bool }
impl Decoded { pub fn bytes(&self) -> &[u8] { &self.bytes[..self.len] } }
impl Marker {
    pub fn clear(&mut self) { self.len = 0; }
    pub fn push(&mut self, byte: u8, pattern: &[u8; 6]) -> Decoded {
        let mut out = Decoded { bytes: [0; 7], len: 0, matched: false };
        self.held[self.len] = byte; self.len += 1;
        if self.held[..self.len] == pattern[..self.len] {
            if self.len == pattern.len() { self.len = 0; out.matched = true; }
            return out;
        }
        // Patterns have no internal ESC. Preserve a final ESC as the next
        // candidate, and emit every other mismatching byte in exact order.
        let keep = usize::from(byte == pattern[0]);
        out.len = self.len - keep;
        out.bytes[..out.len].copy_from_slice(&self.held[..out.len]);
        self.len = keep;
        if keep != 0 { self.held[0] = byte; }
        out
    }
}

#[derive(Debug, Default)]
pub struct Recovery { code: Option<[u8; 16]>, suffix: [u8; 16], len: usize }
impl Recovery {
    pub fn has_code(&self) -> bool { self.code.is_some() }
    pub fn install(&mut self, random: [u8; 8]) -> [u8; 16] {
        let mut code = [0; 16];
        for (i, b) in random.into_iter().enumerate() {
            code[i * 2] = b"0123456789abcdef"[(b >> 4) as usize];
            code[i * 2 + 1] = b"0123456789abcdef"[(b & 15) as usize];
        }
        self.code = Some(code); self.len = 0; code
    }
    pub fn push(&mut self, b: u8) -> bool {
        if b == b'\n' || b == b'\r' {
            let yes = self.len == 16 && self.code.as_ref() == Some(&self.suffix);
            self.len = 0; return yes;
        }
        if self.len == 16 { self.suffix.copy_within(1.., 0); self.len -= 1; }
        self.suffix[self.len] = b; self.len += 1; false
    }
}


/// Only the already-written prefix matters on cancellation. A reader may
/// be blocked inside a declared record: finish its header and newline-pad
/// its remaining payload so the shell reaches the cancellation fence.
/// A mode-0 pause/drain resets this cursor because no reader remains in
/// read_exact then. No source, descriptor or execution queue is retained.
#[derive(Debug, Default)]
pub struct RecordWrite { header: Vec<u8>, remaining: usize }
impl RecordWrite {
    pub fn written(&mut self, bytes: &[u8]) {
        for &b in bytes {
            if self.remaining > 0 { self.remaining -= 1; continue; }
            if self.header.is_empty() {
                if b == RECORD_PREFIX.as_bytes()[0] { self.header.push(b); }
                continue;
            }
            if self.header.len() < RECORD_PREFIX.len() {
                if b == RECORD_PREFIX.as_bytes()[self.header.len()] { self.header.push(b); }
                else { self.header.clear(); }
            } else if b == b'\n' {
                self.remaining = std::str::from_utf8(&self.header[RECORD_PREFIX.len()..]).ok()
                    .and_then(|s| s.parse().ok()).filter(|n| *n <= MAX_SOURCE).unwrap_or(0);
                self.header.clear();
            } else if b.is_ascii_digit() && self.header.len() < record::MAX_HEADER - 1 { self.header.push(b); }
            else { self.header.clear(); }
        }
    }
    pub fn cancel_padding(&self, queued: &[u8]) -> Option<(Vec<u8>, usize)> {
        if self.remaining > 0 { return Some((Vec::new(), self.remaining)); }
        if self.header.is_empty() { return None; }
        let end = queued.iter().take(record::MAX_HEADER).position(|&b| b == b'\n')? + 1;
        let tail = &queued[..end];
        let header = [self.header.as_slice(), tail].concat();
        let len = std::str::from_utf8(header.strip_prefix(RECORD_PREFIX.as_bytes())?.strip_suffix(b"\n")?).ok()?.parse().ok()?;
        if len > MAX_SOURCE { return None; }
        Some((tail.to_vec(), len))
    }
}

#[cfg(test)]
mod record_tests {
    use super::*;
    #[test] fn every_written_cut_preserves_a_partial_record_without_preserving_its_suffix() {
        let payload=b"echo must-not-run\necho second\n";
        let wire=[record::header(payload.len()),payload.to_vec()].concat();
        for cut in 0..=wire.len() {
            let mut tracker=RecordWrite::default(); tracker.written(&wire[..cut]);
            let padded=tracker.cancel_padding(&wire[cut..]);
            if cut==0 || cut==wire.len() {assert!(padded.is_none());continue;}
            let (header,n)=padded.unwrap();let mut rest=header;rest.resize(rest.len()+n,b'\n');
            assert_eq!(cut+rest.len(),wire.len());
            tracker.written(&rest);assert!(tracker.cancel_padding(b"later bytes").is_none());
        }
    }
}
