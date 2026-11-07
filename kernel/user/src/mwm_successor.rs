//! One owner-granted stream per client, two FIFO slots, synchronous strip effects.
pub const RECORD: usize = 256;
pub const WIDTH: usize = 320;
pub const HEIGHT: usize = 200;
pub const ROWS: usize = 40;
pub const FRAME: usize = WIDTH * HEIGHT;
pub const CHUNKS: usize = 1 + (FRAME - 200).div_ceil(240);
pub const DEPTH: usize = 2;

fn put(out: &mut [u8], at: usize, value: u64) {
    out[at..at + 8].copy_from_slice(&value.to_le_bytes());
}
fn get(input: &[u8], at: usize) -> u64 {
    u64::from_le_bytes(input[at..at + 8].try_into().unwrap())
}
fn base(kind: u16, session: u64, generation: u64, sequence: u64) -> [u8; RECORD] {
    let mut r = [0; RECORD];
    r[..4].copy_from_slice(b"MFR1");
    r[4..6].copy_from_slice(&1u16.to_le_bytes());
    r[6..8].copy_from_slice(&kind.to_le_bytes());
    put(&mut r, 8, session);
    put(&mut r, 16, generation);
    put(&mut r, 24, sequence);
    r
}
pub fn fnv(bytes: &[u8]) -> u64 {
    bytes.iter().fold(0xcbf29ce484222325, |hash, b| {
        (hash ^ u64::from(*b)).wrapping_mul(0x100000001b3)
    })
}
pub fn header(session: u64, generation: u64, sequence: u64, payload: &[u8; FRAME]) -> [u8; RECORD] {
    let mut r = base(1, session, generation, sequence);
    r[32..36].copy_from_slice(&(FRAME as u32).to_le_bytes());
    r[36..38].copy_from_slice(&(WIDTH as u16).to_le_bytes());
    r[38..40].copy_from_slice(&(HEIGHT as u16).to_le_bytes());
    r[40] = 1; // RGB332; scene 0
    r[42..44].copy_from_slice(&(CHUNKS as u16).to_le_bytes());
    r[44..46].copy_from_slice(&56u16.to_le_bytes());
    put(&mut r, 48, fnv(payload));
    r[56..].copy_from_slice(&payload[..200]);
    r
}
pub fn chunk(
    session: u64,
    generation: u64,
    sequence: u64,
    index: usize,
    payload: &[u8; FRAME],
) -> [u8; RECORD] {
    assert!(index > 0 && index < CHUNKS);
    let identity = base(1, session, generation, sequence);
    let mut r = [0; RECORD];
    r[..8].copy_from_slice(&base(3, 0, 0, 0)[..8]);
    r[8..10].copy_from_slice(&(index as u16).to_le_bytes());
    r[12..16].copy_from_slice(&(fnv(&identity[8..32]) as u32).to_le_bytes());
    let start = 200 + (index - 1) * 240;
    let count = (FRAME - start).min(240);
    r[16..16 + count].copy_from_slice(&payload[start..start + count]);
    r
}
pub fn trailer(session: u64, generation: u64, sequence: u64, ticks: u64) -> [u8; RECORD] {
    let mut r = base(2, session, generation, sequence);
    put(&mut r, 32, ticks); // evidence only
    r[40..44].copy_from_slice(&(CHUNKS as u32).to_le_bytes());
    r
}
pub fn completion(session: u64, generation: u64, sequence: u64) -> [u8; RECORD] {
    base(4, session, generation, sequence)
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Fault {
    Malformed,
    Full,
    Closed,
    Display,
    Mask,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum End {
    Orderly,
    UnexpectedEof,
    Timeout,
    Malformed,
    Io,
    Revoked,
}
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct Ledger {
    pub accepted: u64,
    pub presented: u64,
    pub failed: u64,
    pub unknown: u64,
    pub discarded: u64,
    pub revoked: u64,
    /// Valid complete stale frames refused before admission; outside accepted.
    pub refused_revoked: u64,
}
#[derive(Debug)]
pub struct SinkError;
pub trait Sink {
    /// Select immutable per-client placement before any strip or redraw.
    fn select(&mut self, _client: usize) {}
    /// One synchronous all-or-nothing strip; no outstanding write after return.
    fn strip(&mut self, sequence: u64, row: usize, pixels: &[u8]) -> Result<(), SinkError>;
    fn mask(&mut self) -> Result<(), SinkError>;
}

pub struct Consumer {
    grant: Option<(u64, u64)>,
    high_water: u64,
    last_complete: u64,
    revoked: bool,
    record: [u8; RECORD],
    len: usize,
    staging: [u8; FRAME],
    sequence: u64,
    hash: u64,
    next: usize,
    ready: bool,
    payloads: [[u8; FRAME]; DEPTH],
    sequences: [u64; DEPTH],
    head: usize,
    count: usize,
    flight: bool,
    last_pixels: [u8; FRAME],
    last_sequence: Option<u64>,
    completion_pending: bool,
    end: Option<End>,
    mask_required: bool,
    pub ledger: Ledger,
}
impl Consumer {
    pub const fn new_const() -> Self {
        Self {
            grant: None,
            high_water: 0,
            last_complete: 0,
            revoked: false,
            record: [0; RECORD],
            len: 0,
            staging: [0; FRAME],
            sequence: 0,
            hash: 0,
            next: 0,
            ready: false,
            payloads: [[0; FRAME]; DEPTH],
            sequences: [0; DEPTH],
            head: 0,
            count: 0,
            flight: false,
            last_pixels: [0; FRAME],
            last_sequence: None,
            completion_pending: false,
            end: None,
            mask_required: false,
            ledger: Ledger {
                accepted: 0,
                presented: 0,
                failed: 0,
                unknown: 0,
                discarded: 0,
                revoked: 0,
                refused_revoked: 0,
            },
        }
    }
    pub fn grant(&mut self, session: u64, generation: u64) -> Result<(), Fault> {
        if self.grant.is_some()
            || self.end.is_some()
            || self.revoked
            || session == 0
            || generation == 0
        {
            return Err(Fault::Closed);
        }
        self.grant = Some((session, generation));
        Ok(())
    }
    pub fn end_reason(&self) -> Option<End> {
        self.end
    }
    pub fn high_water(&self) -> u64 {
        self.high_water
    }
    pub fn queued(&self) -> usize {
        self.count
    }
    pub fn front_sequence(&self) -> Option<u64> {
        if self.count == 0 {
            None
        } else {
            Some(self.sequences[self.head])
        }
    }
    pub fn last_presented(&self) -> Option<u64> {
        self.last_sequence
    }
    pub fn mask_required(&self) -> bool {
        self.mask_required
    }
    pub fn revocation_complete(&self) -> bool {
        self.revoked && !self.mask_required
    }
    /// Tombstone authority before masking. A failed mask may be retried;
    /// program order puts this mask after every synchronous strip return.
    pub fn revoke(&mut self, sink: &mut impl Sink) -> Result<(), Fault> {
        if !self.revoked {
            self.revoked = true;
            self.last_sequence = None;
            self.ledger.revoked += self.count as u64;
            self.count = 0;
            self.mask_required = true;
            if self.ready {
                self.admit_ready()?;
            }
        }
        if self.mask_required {
            sink.mask().map_err(|_| Fault::Mask)?;
            self.mask_required = false;
        }
        assert!(self.balanced());
        Ok(())
    }
    /// Conservation of admitted frames only; does not require contiguous sequences.
    pub fn balanced(&self) -> bool {
        let l = self.ledger;
        l.accepted
            == l.presented
                + l.failed
                + l.unknown
                + l.discarded
                + l.revoked
                + self.count as u64
                + u64::from(self.flight)
    }
    fn discard(&mut self, reason: End) {
        self.last_sequence = None;
        self.ledger.discarded += self.count as u64;
        self.count = 0;
        self.next = 0;
        self.ready = false;
        self.len = 0;
        self.grant = None;
        self.end = Some(reason);
        assert!(self.balanced());
    }
    /// Supply arbitrary fragments, including reads crossing 1 KiB boundaries.
    /// Return bytes consumed, retaining a complete staged frame under backpressure.
    /// Retry the unread tail after making room and calling admit_ready.
    pub fn bytes(&mut self, mut bytes: &[u8]) -> Result<usize, Fault> {
        if self.end.is_some() {
            return Err(Fault::Closed);
        }
        if self.ready {
            return Ok(0);
        }
        let supplied = bytes.len();
        while !bytes.is_empty() {
            if self.completion_pending {
                self.discard(End::Malformed);
                return Err(Fault::Malformed);
            }
            let n = bytes.len().min(RECORD - self.len);
            self.record[self.len..self.len + n].copy_from_slice(&bytes[..n]);
            self.len += n;
            bytes = &bytes[n..];
            if self.len == RECORD {
                self.len = 0;
                let r = self.record;
                if let Err(e) = self.record(&r) {
                    if e == Fault::Full {
                        return Ok(supplied - bytes.len());
                    }
                    self.discard(End::Malformed);
                    return Err(e);
                }
            }
        }
        Ok(supplied)
    }
    fn record(&mut self, r: &[u8; RECORD]) -> Result<(), Fault> {
        let (session, generation) = self.grant.ok_or(Fault::Malformed)?;
        if &r[..6] != b"MFR1\x01\x00" {
            return Err(Fault::Malformed);
        }
        let kind = u16::from_le_bytes([r[6], r[7]]);
        if kind == 4 {
            if self.next != 0 || r != &completion(session, generation, self.last_complete) {
                return Err(Fault::Malformed);
            }
            self.completion_pending = true;
            return Ok(());
        }
        if self.next == 0 {
            if kind != 1
                || get(r, 8) != session
                || get(r, 16) != generation
                || get(r, 24) <= self.last_complete
            {
                return Err(Fault::Malformed);
            }
            self.sequence = get(r, 24);
            self.hash = get(r, 48);
            // Canonical header validates geometry, reserved bytes and format.
            let canonical = header(session, generation, self.sequence, &self.staging);
            if r[32..48] != canonical[32..48] {
                return Err(Fault::Malformed);
            }
            self.staging[..200].copy_from_slice(&r[56..]);
            self.next = 1;
        } else if self.next < CHUNKS {
            let expected = chunk(session, generation, self.sequence, self.next, &self.staging);
            if kind != 3 || r[..16] != expected[..16] {
                return Err(Fault::Malformed);
            }
            let start = 200 + (self.next - 1) * 240;
            let count = (FRAME - start).min(240);
            if r[16 + count..].iter().any(|b| *b != 0) {
                return Err(Fault::Malformed);
            }
            self.staging[start..start + count].copy_from_slice(&r[16..16 + count]);
            self.next += 1;
        } else {
            if r != &trailer(session, generation, self.sequence, get(r, 32))
                || fnv(&self.staging) != self.hash
            {
                return Err(Fault::Malformed);
            }
            self.ready = true;
            self.admit_ready()?;
        }
        Ok(())
    }
    pub fn admit_ready(&mut self) -> Result<(), Fault> {
        if !self.ready {
            return Err(Fault::Malformed);
        }
        if self.revoked {
            self.ledger.refused_revoked += 1;
            self.last_complete = self.sequence;
            self.next = 0;
            self.ready = false;
            return Ok(());
        }
        if self.count == DEPTH {
            return Err(Fault::Full);
        }
        let tail = (self.head + self.count) % DEPTH;
        self.payloads[tail].copy_from_slice(&self.staging);
        self.sequences[tail] = self.sequence;
        self.count += 1;
        self.high_water = self.sequence;
        self.last_complete = self.sequence;
        self.ledger.accepted += 1;
        self.next = 0;
        self.ready = false;
        assert!(self.balanced());
        Ok(())
    }
    /// EOF validates a pending completion only at a clean record boundary.
    /// Timeout and I/O failure are never completion, even after kind 4.
    pub fn end(&mut self, reason: End) -> End {
        if let Some(end) = self.end {
            // Peer retirement can fail after clean EOF, before any drain.
            if end == End::Orderly && matches!(reason, End::Io | End::Timeout) {
                self.discard(reason);
                return reason;
            }
            return end;
        }
        if reason == End::UnexpectedEof && self.completion_pending && self.len == 0 {
            self.end = Some(End::Orderly);
            End::Orderly
        } else {
            let reason = if reason == End::Orderly {
                End::Malformed
            } else {
                reason
            };
            self.discard(reason);
            reason
        }
    }
    pub fn present_one(&mut self, sink: &mut impl Sink) -> Result<(), Fault> {
        if self.grant.is_none()
            || self.revoked
            || self.mask_required
            || !matches!(self.end, None | Some(End::Orderly))
            || self.count == 0
        {
            return Err(Fault::Closed);
        }
        // Transfer queue ownership to flight BEFORE effect; terminal only after return.
        let slot = self.head;
        self.head = (self.head + 1) % DEPTH;
        self.count -= 1;
        self.flight = true;
        assert!(self.balanced());
        if let Err(row) = draw(&self.payloads[slot], self.sequences[slot], sink) {
            self.flight = false;
            if row == 0 {
                self.ledger.failed += 1;
            } else {
                self.ledger.unknown += 1;
                self.mask_required = true;
            }
            self.discard(End::Io);
            if self.mask_required {
                sink.mask().map_err(|_| Fault::Mask)?;
                self.mask_required = false;
            }
            return Err(Fault::Display);
        }
        self.last_pixels.copy_from_slice(&self.payloads[slot]);
        self.last_sequence = Some(self.sequences[slot]);
        self.flight = false;
        self.ledger.presented += 1;
        assert!(self.balanced());
        Ok(())
    }
    /// Replay visibility only: no new admitted-frame obligation or ledger change.
    pub fn redraw(&self, sink: &mut impl Sink) -> Result<(), Fault> {
        if self.grant.is_some()
            && !self.revoked
            && !self.mask_required
            && matches!(self.end, None | Some(End::Orderly))
            && let Some(sequence) = self.last_sequence
        {
            draw(&self.last_pixels, sequence, sink).map_err(|_| Fault::Display)?;
        }
        Ok(())
    }
    pub fn drain(&mut self, sink: &mut impl Sink) -> Result<(), Fault> {
        if self.end != Some(End::Orderly) || self.revoked {
            return Err(Fault::Closed);
        }
        // Count-bound drain: at most depth dequeues, no reads, grant checked each time.
        for _ in 0..DEPTH {
            if self.count == 0 {
                break;
            }
            self.present_one(sink)?;
        }
        assert_eq!(self.count, 0);
        Ok(())
    }
}

fn draw(payload: &[u8; FRAME], sequence: u64, sink: &mut impl Sink) -> Result<(), usize> {
    let mut pixels = [0; WIDTH * ROWS * 4];
    for row in (0..HEIGHT).step_by(ROWS) {
        for (i, color) in payload[row * WIDTH..(row + ROWS) * WIDTH]
            .iter()
            .enumerate()
        {
            pixels[i * 4..i * 4 + 4].copy_from_slice(&[
                (*color & 3) << 6,
                *color & 0x1c,
                *color & 0xe0,
                0,
            ]);
        }
        sink.strip(sequence, row, &pixels).map_err(|_| row)?;
    }
    Ok(())
}

/// One bounded readiness poll per visit; retain the caller-owned unread tail.
pub trait Stream {
    fn poll(&mut self, consumer: &mut Consumer) -> Result<(), End>;
}
pub struct Pump {
    next: usize,
    pub retired: [bool; 2],
    pub visits: [u64; 2],
}
impl Default for Pump {
    fn default() -> Self {
        Self::new()
    }
}
impl Pump {
    pub const fn new() -> Self {
        Self {
            next: 0,
            retired: [false; 2],
            visits: [0; 2],
        }
    }
    pub fn revoke(
        &mut self,
        client: usize,
        clients: &mut [Consumer; 2],
        sink: &mut impl Sink,
    ) -> Result<(), Fault> {
        sink.select(client);
        clients[client].revoke(sink)?;
        clients[client].end(End::Revoked);
        self.retired[client] = true;
        // Whole-display mask: redraw only clients still authorized, from last success.
        for (i, c) in clients.iter().enumerate() {
            sink.select(i);
            c.redraw(sink)?;
        }
        Ok(())
    }
    pub fn turn(
        &mut self,
        clients: &mut [Consumer; 2],
        streams: &mut [impl Stream; 2],
        sink: &mut impl Sink,
    ) -> Result<(), Fault> {
        for offset in 0..2 {
            let i = (self.next + offset) % 2;
            if self.retired[i] {
                continue;
            }
            self.visits[i] += 1;
            if clients[i].end_reason().is_none()
                && let Err(reason) = streams[i].poll(&mut clients[i])
            {
                clients[i].end(reason);
            }
            if matches!(clients[i].end_reason(), None | Some(End::Orderly))
                && clients[i].queued() != 0
            {
                sink.select(i);
                match clients[i].present_one(sink) {
                    Ok(()) => {}
                    Err(Fault::Mask) => return Err(Fault::Mask),
                    Err(_) => {
                        clients[i].end(End::Io);
                    }
                }
                if clients[i].ready && clients[i].end_reason().is_none() {
                    clients[i].admit_ready()?;
                }
            }
            if !matches!(clients[i].end_reason(), None | Some(End::Orderly)) {
                self.revoke(i, clients, sink)?;
            }
        }
        self.next = 1 - self.next;
        Ok(())
    }
}

/// Sole-reader readiness: an idle live writer never causes a blocking read.
/// Zero writers with no bytes permits the definitive EOF read.
pub fn ready_read(available: usize, writers: usize, limit: usize) -> Option<usize> {
    if available == 0 && writers != 0 {
        None
    } else {
        Some(available.min(limit).max(1))
    }
}
