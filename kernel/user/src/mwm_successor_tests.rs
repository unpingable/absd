#[path = "mwm_successor.rs"]
mod transport;
use transport::*;

#[derive(Default)]
struct Display {
    calls: Vec<(u64, usize)>,
    fail: Option<usize>,
    masks: usize,
    mask_fail: bool,
}
impl Sink for Display {
    fn strip(&mut self, sequence: u64, row: usize, pixels: &[u8]) -> Result<(), SinkError> {
        assert_eq!(pixels.len(), WIDTH * ROWS * 4);
        for (i, pixel) in pixels.chunks_exact(4).enumerate() {
            let color = pixel_color(sequence, row * WIDTH + i);
            assert_eq!(pixel, &[(color & 3) << 6, color & 0x1c, color & 0xe0, 0]);
        }
        self.calls.push((sequence, row));
        if self.fail == Some(self.calls.len()) {
            Err(SinkError)
        } else {
            Ok(())
        }
    }
    fn mask(&mut self) -> Result<(), SinkError> {
        self.masks += 1;
        if self.mask_fail {
            Err(SinkError)
        } else {
            Ok(())
        }
    }
}
fn pixel_color(sequence: u64, i: usize) -> u8 {
    (sequence as u8)
        .wrapping_mul(31)
        .wrapping_add((i / WIDTH + i % WIDTH) as u8)
}
fn records(sequence: u64) -> Vec<[u8; RECORD]> {
    records_for(17, 1, sequence)
}
fn records_for(session: u64, generation: u64, sequence: u64) -> Vec<[u8; RECORD]> {
    let payload = core::array::from_fn(|i| pixel_color(sequence, i));
    let mut records = vec![header(session, generation, sequence, &payload)];
    records.extend((1..CHUNKS).map(|i| chunk(session, generation, sequence, i, &payload)));
    records.push(trailer(session, generation, sequence, 123));
    records
}

#[test]
fn b_keeps_presenting_across_a_revocation() {
    for orderly in [false, true] {
        for mask_fail in [false, true] {
            let mut a = consumer();
            let mut b = Consumer::new_const();
            b.grant(29, 7).unwrap();
            let mut d = Display::default();
            feed(&mut a, 1);
            a.present_one(&mut d).unwrap();
            for r in records_for(29, 7, 10) { b.bytes(&r).unwrap(); }
            b.present_one(&mut d).unwrap();
            feed(&mut a, 2);
            feed(&mut a, 3);
            if orderly { finish(&mut a, 3); }
            d.mask_fail = mask_fail;
            assert_eq!(a.revoke(&mut d), if mask_fail {Err(Fault::Mask)} else {Ok(())});
            assert_eq!(a.revocation_complete(), !mask_fail);
            assert_eq!((a.ledger.revoked, a.queued()), (2, 0));
            let calls = d.calls.len();
            assert_eq!(a.present_one(&mut d), Err(Fault::Closed));
            assert_eq!(d.calls.len(), calls);
            assert!(a.grant(17, 2).is_err());
            if mask_fail {
                d.mask_fail = false;
                a.revoke(&mut d).unwrap();
                assert!(a.revocation_complete());
            }
            for sequence in [11, 12] {
                for r in records_for(29, 7, sequence) { b.bytes(&r).unwrap(); }
                b.present_one(&mut d).unwrap();
            }
            if !orderly {
                feed(&mut a, 4); // valid old grant, refused without acquiring a queue slot
                assert_eq!((a.high_water(), a.ledger.refused_revoked), (3, 1));
                finish(&mut a, 4);
            }
            assert_eq!(a.drain(&mut d), Err(Fault::Closed));
            assert_eq!(a.ledger.presented, 1);
            assert_eq!((b.ledger.accepted, b.ledger.presented, b.ledger.revoked), (3, 3, 0));
            assert_eq!(d.calls.len(), 4 * HEIGHT / ROWS);
            assert!(a.balanced() && b.balanced());
        }
    }
}

#[test]
fn revoke_partial_and_staged_frame() {
    let mut ungranted = Consumer::new_const();
    ungranted.revoke(&mut Display::default()).unwrap();
    assert_eq!(ungranted.grant(17, 1), Err(Fault::Closed));
    let wire = records(1);
    for split in [1, 200, 256, wire.len() * RECORD - 1] {
        let mut c = consumer();
        let bytes: Vec<u8> = wire.iter().flatten().copied().collect();
        assert_eq!(c.bytes(&bytes[..split]), Ok(split));
        c.revoke(&mut Display::default()).unwrap();
        assert_eq!(c.bytes(&bytes[split..]), Ok(bytes.len() - split));
        finish(&mut c, 1);
        assert_eq!((c.ledger.accepted, c.ledger.refused_revoked), (0, 1));
        assert!(c.balanced() && c.revocation_complete());
    }
    let mut c = consumer();
    feed(&mut c, 1);
    feed(&mut c, 2);
    feed(&mut c, 3); // third complete frame staged by backpressure
    c.revoke(&mut Display::default()).unwrap();
    assert_eq!((c.ledger.revoked, c.ledger.refused_revoked), (2, 1));
    finish(&mut c, 3);
    assert!(c.balanced());
}
fn consumer() -> Consumer {
    let mut c = Consumer::new_const();
    c.grant(17, 1).unwrap();
    c
}
fn feed(c: &mut Consumer, sequence: u64) {
    for record in records(sequence) {
        c.bytes(&record).unwrap();
    }
}
fn finish(c: &mut Consumer, sequence: u64) {
    c.bytes(&completion(17, 1, sequence)).unwrap();
    assert_eq!(c.end(End::UnexpectedEof), End::Orderly);
}
#[test]
fn completion_records() {
    // A caller cannot declare completion without validated kind 4 and EOF.
    for pending in [false, true] {
        let mut c = consumer();
        feed(&mut c, 1);
        if pending {
            c.bytes(&completion(17, 1, 1)).unwrap();
        }
        assert_eq!(c.end(End::Orderly), End::Malformed);
        assert_eq!(c.end_reason(), Some(End::Malformed));
        assert_eq!((c.queued(), c.ledger.discarded), (0, 1));
        assert!(c.balanced());
        assert!(c.drain(&mut Display::default()).is_err());
    }
    for fragment in [1, 7, 255, 256, 1024] {
        let mut c = consumer();
        let mut wire: Vec<u8> = records(1).into_iter().flatten().collect();
        wire.extend(completion(17, 1, 1));
        for bytes in wire.chunks(fragment) {
            c.bytes(bytes).unwrap();
        }
        assert_eq!(c.end(End::UnexpectedEof), End::Orderly);
        let mut d = Display::default();
        c.drain(&mut d).unwrap();
        assert_eq!(c.ledger.presented, 1);
        assert_eq!(d.calls.len(), HEIGHT / ROWS);
        assert!(c.balanced());
        assert_eq!(c.bytes(&[0]), Err(Fault::Closed));
    }
    for mutation in [0, 4, 8, 16, 24, 32, 255] {
        let mut c = consumer();
        feed(&mut c, 1);
        let mut done = completion(17, 1, 1);
        done[mutation] ^= 1;
        assert_eq!(c.bytes(&done), Err(Fault::Malformed));
        assert_eq!((c.ledger.discarded, c.queued()), (1, 0));
    }
    for count in [0, 1, 255] {
        let mut c = consumer();
        feed(&mut c, 1);
        c.bytes(&completion(17, 1, 1)[..count]).unwrap();
        assert_eq!(c.end(End::UnexpectedEof), End::UnexpectedEof);
        assert_eq!(c.ledger.discarded, 1);
    }
    for extra in [vec![0], completion(17, 1, 1).to_vec()] {
        let mut c = consumer();
        feed(&mut c, 1);
        c.bytes(&completion(17, 1, 1)).unwrap();
        assert_eq!(c.bytes(&extra), Err(Fault::Malformed));
        assert_eq!(c.ledger.discarded, 1);
    }
    for end in [End::Timeout, End::Io] {
        let mut c = consumer();
        feed(&mut c, 1);
        c.bytes(&completion(17, 1, 1)).unwrap();
        assert_eq!(c.end(end), end);
        assert_eq!(c.ledger.discarded, 1);
        assert!(c.present_one(&mut Display::default()).is_err());
    }
    let mut c = consumer();
    c.bytes(&records(1)[0]).unwrap();
    assert_eq!(c.bytes(&completion(17, 1, 0)), Err(Fault::Malformed));
    let mut c = consumer();
    finish(&mut c, 0);
    c.drain(&mut Display::default()).unwrap();
}
#[test]
fn ownership_ledger() {
    let mut c = consumer();
    let mut d = Display::default();
    let mut observed = Vec::new();
    for sequence in 1..=6 {
        feed(&mut c, sequence);
        observed.push(sequence);
        assert_eq!(c.ledger.accepted as usize, observed.len());
        assert!(c.balanced());
        if sequence % 2 == 0 {
            for expected in sequence - 1..=sequence {
                assert_eq!(c.front_sequence(), Some(expected));
                c.present_one(&mut d).unwrap();
                assert!(c.balanced());
            }
        }
    }
    assert_eq!(
        d.calls
            .iter()
            .step_by(HEIGHT / ROWS)
            .map(|(s, _)| *s)
            .collect::<Vec<_>>(),
        observed
    );
    assert_eq!(c.ledger.presented, 6);
    assert_eq!(c.high_water(), 6);
    finish(&mut c, 6);
    c.drain(&mut d).unwrap();
    let before = c.ledger;
    assert!(c.present_one(&mut d).is_err());
    assert_eq!(c.ledger, before);

    let mut c = consumer();
    feed(&mut c, 1);
    feed(&mut c, 2);
    let r = records(3);
    for record in &r[..r.len() - 1] {
        c.bytes(record).unwrap();
    }
    assert_eq!(c.bytes(r.last().unwrap()), Ok(RECORD));
    assert_eq!(c.bytes(&[0]), Ok(0)); // caller still owns this byte
    assert_eq!((c.high_water(), c.ledger.accepted, c.queued()), (2, 2, 2));
    c.present_one(&mut d).unwrap();
    c.admit_ready().unwrap();
    assert_eq!((c.high_water(), c.ledger.accepted, c.queued()), (3, 3, 2));
    finish(&mut c, 3);
    c.drain(&mut d).unwrap();
    assert_eq!(c.ledger.presented, 3);
    assert!(c.balanced());

    let mut c = consumer();
    feed(&mut c, 1);
    assert_eq!(c.bytes(&records(1)[0]), Err(Fault::Malformed));
    assert_eq!((c.high_water(), c.ledger.discarded), (1, 1));
    assert!(c.balanced());
}
#[test]
fn strip_failure() {
    for failed_call in 1..=HEIGHT / ROWS {
        for mask_fail in [false, true] {
            let mut c = consumer();
            feed(&mut c, 1);
            feed(&mut c, 2);
            finish(&mut c, 2);
            let mut d = Display {
                fail: Some(failed_call),
                mask_fail,
                ..Display::default()
            };
            assert!(c.drain(&mut d).is_err());
            assert_eq!(
                (c.ledger.failed, c.ledger.unknown),
                if failed_call == 1 { (1, 0) } else { (0, 1) }
            );
            assert_eq!(c.ledger.discarded, 1);
            assert_eq!(d.calls.len(), failed_call);
            assert_eq!(d.masks, usize::from(failed_call > 1));
            assert_eq!(c.mask_required(), failed_call > 1 && mask_fail);
            assert_eq!(c.ledger.presented, 0);
            assert!(c.balanced());
        }
    }
}
#[test]
fn construction_restart() {
    for _ in 0..2 {
        let mut c = Consumer::new_const();
        assert_eq!((c.high_water(), c.queued()), (0, 0));
        assert!(c.balanced());
        assert!(c.bytes(&records(1)[0]).is_err());
        let mut c = Consumer::new_const();
        assert!(c.grant(0, 1).is_err());
        c.grant(17, 1).unwrap();
        assert!(c.grant(17, 2).is_err());
        feed(&mut c, 1);
        finish(&mut c, 1);
        c.drain(&mut Display::default()).unwrap();
        assert_eq!(c.ledger.presented, 1);
    }
}

#[test]
fn retirement_after_orderly() {
    for reason in [End::Timeout, End::Io] {
    let mut c = consumer();
    feed(&mut c, 1);
    feed(&mut c, 2);
    finish(&mut c, 2);
    assert_eq!(c.end(reason), reason);
    assert_eq!(c.end_reason(), Some(reason));
    assert_eq!((c.queued(), c.ledger.discarded), (0, 2));
    assert!(c.balanced());
    assert!(c.drain(&mut Display::default()).is_err());
    }
}

#[test]
fn odd_reads_under_backpressure() {
    for size in [7, 255, 256, 1000, 1024] {
        let mut c = consumer();
        let mut d = Display::default();
        let mut wire: Vec<u8> = (1..=4).flat_map(records).flatten().collect();
        wire.extend(completion(17, 1, 4));
        for read in wire.chunks(size) {
            let mut tail = read;
            while !tail.is_empty() {
                let consumed = c.bytes(tail).unwrap();
                tail = &tail[consumed..];
                if consumed == 0 {
                    c.present_one(&mut d).unwrap();
                    c.admit_ready().unwrap();
                }
            }
        }
        assert_eq!(c.end(End::UnexpectedEof), End::Orderly);
        c.drain(&mut d).unwrap();
        assert_eq!((c.ledger.accepted, c.ledger.presented), (4, 4));
        assert!(c.balanced());
    }
}
fn rejected(records: &[[u8; RECORD]]) {
    let mut c = consumer();
    let mut bad = false;
    for record in records {
        if c.bytes(record).is_err() {
            bad = true;
            break;
        }
    }
    assert!(bad || c.end(End::UnexpectedEof) != End::Orderly);
    assert_eq!(c.queued(), 0);
    assert!(c.balanced());
}
#[test]
fn wire_rejection() {
    let mut valid = records(1);
    valid.push(completion(17, 1, 1));
    // Every header/chunk/trailer byte is checked, except trailer ticks (evidence).
    for record in 0..valid.len() - 1 {
        for byte in 0..RECORD {
            if record == CHUNKS && (32..40).contains(&byte) {
                continue;
            }
            let mut wire = valid.clone();
            wire[record][byte] ^= 1;
            // A sequence change is also rejected by the remaining record identities.
            rejected(&wire);
        }
    }
    for (session, generation) in [(18, 1), (17, 2)] {
        let payload = core::array::from_fn(|i| pixel_color(1, i));
        let mut wire = vec![header(session, generation, 1, &payload)];
        wire.extend((1..CHUNKS).map(|i| chunk(session, generation, 1, i, &payload)));
        wire.push(trailer(session, generation, 1, 0));
        wire.push(completion(session, generation, 1));
        rejected(&wire);
    }
    let mut wire = valid.clone();
    wire.swap(1, 2);
    rejected(&wire);
    let mut wire = valid.clone();
    wire.remove(1);
    rejected(&wire);
    let mut wire = valid.clone();
    wire[1] = records(2)[1];
    rejected(&wire);
    let mut c = consumer();
    for r in &valid {
        c.bytes(r).unwrap();
    }
    assert_eq!(c.bytes(&[1]), Err(Fault::Malformed));
    assert_eq!((c.queued(), c.ledger.discarded), (0, 1));
}

// A real strip framebuffer: masks erase both surfaces, redraw must restore B
// without another admitted/presented obligation and must never restore retired A.
#[derive(Default)]
struct Surfaces {
    selected: usize,
    pixels: [Vec<u8>; 2],
    masks: usize,
    fail_mask: bool,
    fail_strip: Option<(usize,usize)>,
}
impl Sink for Surfaces {
    fn select(&mut self, client: usize) { self.selected = client; }
    fn strip(&mut self, _: u64, row: usize, pixels: &[u8]) -> Result<(), SinkError> {
        if self.fail_strip == Some((self.selected,row)) { return Err(SinkError); }
        self.pixels[self.selected].resize(FRAME * 4, 0);
        let start = row * WIDTH * 4;
        self.pixels[self.selected][start..start + pixels.len()].copy_from_slice(pixels);
        Ok(())
    }
    fn mask(&mut self) -> Result<(), SinkError> {
        self.masks += 1;
        if self.fail_mask { return Err(SinkError); }
        for p in &mut self.pixels { p.fill(0); }
        Ok(())
    }
}
struct Wire {
    bytes: Vec<u8>,
    offset: usize,
    size: usize,
    end: Option<End>,
    polls: usize,
}
impl Stream for Wire {
    fn poll(&mut self, c: &mut Consumer) -> Result<(), End> {
        self.polls += 1;
        if self.offset == self.bytes.len() {
            if let Some(end) = self.end { c.end(end); }
            return Ok(());
        }
        let end = (self.offset + self.size).min(self.bytes.len());
        self.offset += c.bytes(&self.bytes[self.offset..end]).map_err(|_| End::Malformed)?;
        Ok(())
    }
}
fn wires(a: usize, b: usize, size_a: usize, size_b: usize) -> [Wire; 2] {
    core::array::from_fn(|i| Wire {
        bytes: (1..=[a,b][i]).flat_map(|s| records_for([17,29][i], 1, s as u64)).flatten().collect(),
        offset: 0, size: [size_a,size_b][i], end: None, polls: 0,
    })
}
fn pair() -> [Consumer; 2] {
    let mut clients = [Consumer::new_const(), Consumer::new_const()];
    clients[0].grant(17, 1).unwrap(); clients[1].grant(29, 1).unwrap();
    clients
}
#[test]
fn isolated_faults_recompose_survivor() {
    for end in [End::Malformed, End::UnexpectedEof, End::Io, End::Timeout] {
        let mut clients = pair(); let mut pump = Pump::new();
        let mut wires = wires(1, 1, RECORD * (CHUNKS + 1), RECORD * (CHUNKS + 1));
        let mut d = Surfaces::default();
        pump.turn(&mut clients, &mut wires, &mut d).unwrap();
        assert_eq!(clients[1].last_presented(), Some(1));
        let b_pixels = d.pixels[1].clone(); let b_ledger = clients[1].ledger;
        assert!(!b_pixels.is_empty());
        // Accepted A2 is discarded when A's next read faults. No B2 is available.
        feed(&mut clients[0], 2);
        if end == End::Malformed { wires[0].bytes.push(0); wires[0].bytes.extend([0;RECORD-1]); }
        else { wires[0].end = Some(end); }
        pump.turn(&mut clients, &mut wires, &mut d).unwrap();
        assert!(pump.retired[0]); assert!(!pump.retired[1]);
        assert_eq!(clients[0].end_reason(), Some(end));
        assert_eq!((clients[0].ledger.discarded, clients[0].queued()), (1,0));
        assert!(d.pixels[0].iter().all(|b| *b == 0));
        assert_eq!(d.pixels[1], b_pixels); assert_eq!(clients[1].ledger, b_ledger);
        wires[1].bytes.extend(records_for(29, 1, 2).into_iter().flatten());
        pump.turn(&mut clients, &mut wires, &mut d).unwrap();
        assert_eq!(clients[1].ledger.presented, 2);
        assert!(clients.iter().all(Consumer::balanced));
    }
}
#[test]
fn revoke_redraw_never_resurrects_a() {
    let mut clients = pair(); let mut pump = Pump::new();
    let mut wires = wires(1, 1, usize::MAX/2, usize::MAX/2); let mut d = Surfaces::default();
    pump.turn(&mut clients, &mut wires, &mut d).unwrap();
    let b = d.pixels[1].clone(); let ledger = clients[1].ledger;
    feed(&mut clients[0], 2);
    pump.revoke(0, &mut clients, &mut d).unwrap();
    assert!(clients[0].revocation_complete());
    assert_eq!(clients[0].ledger.revoked, 1);
    assert_eq!(clients[1].ledger, ledger); assert_eq!(d.pixels[1], b);
    assert!(d.pixels[0].iter().all(|b| *b == 0));
    // B's later fault masks too; an old retained A frame cannot be restored.
    wires[1].end = Some(End::Io);
    pump.turn(&mut clients, &mut wires, &mut d).unwrap();
    assert!(d.pixels.iter().flatten().all(|b| *b == 0));
    assert_eq!(wires[0].polls, 1); // no stale stream reads after retirement
}

// Keeping the cached sequence on revoke AND ignoring revoked in redraw must
// not restore an Orderly-ended client: end(Revoked) preserves its Orderly end.
#[test]
fn orderly_then_revoked_never_redrawn() {
    let mut clients = pair();
    let mut pump = Pump::new();
    let mut wires = wires(1, 1, RECORD * (CHUNKS + 1), RECORD * (CHUNKS + 1));
    wires[0].bytes.extend(completion(17, 1, 1));
    wires[0].end = Some(End::UnexpectedEof);
    let mut d = Surfaces::default();
    for _ in 0..3 {
        pump.turn(&mut clients, &mut wires, &mut d).unwrap();
    }
    assert_eq!(clients[0].end_reason(), Some(End::Orderly));
    assert!(!pump.retired[0]);
    assert!(d.pixels[0].iter().any(|byte| *byte != 0));
    let b = d.pixels[1].clone();
    let ledger = clients[1].ledger;
    pump.revoke(0, &mut clients, &mut d).unwrap();
    assert!(clients[0].revocation_complete() && pump.retired[0]);
    assert!(d.pixels[0].iter().all(|byte| *byte == 0));
    assert_eq!(d.pixels[1], b);
    assert_eq!(clients[1].ledger, ledger);
    // A must remain masked when B's later fault triggers another replay.
    wires[1].end = Some(End::Io);
    pump.turn(&mut clients, &mut wires, &mut d).unwrap();
    assert!(d.pixels.iter().flatten().all(|byte| *byte == 0));
    assert!(clients.iter().all(Consumer::balanced));
}
#[test]
fn pump_mask_failure_stays_failed() {
    let mut clients = pair(); let mut pump = Pump::new(); let mut d = Surfaces { fail_mask:true, ..Surfaces::default() };
    assert_eq!(pump.revoke(0, &mut clients, &mut d), Err(Fault::Mask));
    assert!(!clients[0].revocation_complete());
    assert!(clients[0].mask_required());
}
#[test]
fn fast_sender_cannot_starve_b() {
    let mut clients = pair(); let mut pump = Pump::new();
    let mut wires = wires(24, 4, 256, 63);
    let mut d = Surfaces::default(); let mut a_when_b_first = None;
    for _ in 0..20_000 {
        pump.turn(&mut clients, &mut wires, &mut d).unwrap();
        assert!(wires[0].polls.abs_diff(wires[1].polls) <= 1);
        if clients[1].ledger.presented > 0 && a_when_b_first.is_none() { a_when_b_first = Some(clients[0].ledger.presented); }
        if clients[0].ledger.presented == 24 && clients[1].ledger.presented == 4 { break; }
    }
    assert_eq!(clients[1].ledger.presented, 4);
    assert!((3..=5).contains(&a_when_b_first.unwrap()));
    assert_eq!(clients[0].ledger.presented, 24);
    assert!(clients.iter().all(Consumer::balanced));
}

#[test]
fn readiness_does_not_read_an_idle_writer() {
    assert_eq!(ready_read(0, 1, 1000), None);
    assert_eq!(ready_read(0, 0, 1000), Some(1));
    assert_eq!(ready_read(7, 1, 1000), Some(7));
    assert_eq!(ready_read(4096, 1, 1000), Some(1000));
    assert_eq!(ready_read(255, 0, 1000), Some(255));
}

#[test]
fn redraw_failure_never_reports_success() {
    let mut clients = pair(); let mut pump = Pump::new();
    let mut wires = wires(1, 1, RECORD*(CHUNKS+1), RECORD*(CHUNKS+1));
    let mut d = Surfaces::default();
    pump.turn(&mut clients, &mut wires, &mut d).unwrap();
    let before = clients[1].ledger;
    d.fail_strip = Some((1,ROWS));
    assert_eq!(pump.revoke(0, &mut clients, &mut d), Err(Fault::Display));
    assert_eq!(clients[1].ledger, before);
    assert!(d.pixels[0].iter().all(|b| *b == 0));
}
#[test]
fn either_client_fault_is_local() {
    for failed in 0..2 {
        let mut clients = pair(); let mut pump = Pump::new();
        let mut wires = wires(1, 1, RECORD*(CHUNKS+1), RECORD*(CHUNKS+1));
        let mut d = Surfaces::default();
        pump.turn(&mut clients, &mut wires, &mut d).unwrap();
        let survivor = 1-failed; let pixels = d.pixels[survivor].clone();
        wires[failed].end = Some(End::Io);
        pump.turn(&mut clients, &mut wires, &mut d).unwrap();
        assert!(pump.retired[failed] && !pump.retired[survivor]);
        assert_eq!(d.pixels[survivor], pixels);
        assert!(d.pixels[failed].iter().all(|b| *b == 0));
        wires[survivor].bytes.extend(records_for([17,29][survivor],1,2).into_iter().flatten());
        pump.turn(&mut clients, &mut wires, &mut d).unwrap();
        assert_eq!(clients[survivor].ledger.presented,2);
    }
}
#[test]
fn partial_frame_is_never_cached_for_redraw() {
    for row in [0, ROWS] {
        let mut clients = pair(); let mut pump = Pump::new();
        let mut wires = wires(1, 1, RECORD*(CHUNKS+1), RECORD*(CHUNKS+1));
        let mut d = Surfaces::default();
        pump.turn(&mut clients, &mut wires, &mut d).unwrap();
        let b = d.pixels[1].clone();
        wires[0].bytes.extend(records(2).into_iter().flatten());
        d.fail_strip = Some((0,row));
        pump.turn(&mut clients, &mut wires, &mut d).unwrap();
        assert_eq!(clients[0].last_presented(), None);
        assert_eq!((clients[0].ledger.failed,clients[0].ledger.unknown), if row==0 {(1,0)} else {(0,1)});
        assert_eq!(d.pixels[1], b);
        assert!(d.pixels[0].iter().all(|b| *b==0));
    }
}
