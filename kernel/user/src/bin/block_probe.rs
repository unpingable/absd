//! Block substrate probe: real sector transfers, the flush barrier, range and
//! rights refusals, and the append region's extent recovery, on a scratch
//! image the harness supplies zero-filled.
#![no_std]
#![no_main]

use absd_user::ledger::Ledger;
use absd_user::{
    BLOCK_MAX_TRANSFER_SECTORS, BLOCK_SECTOR_BYTES, Block, Cell, Console, Error, MultiStart,
    Outcome, Pipe, RIGHT_KILL, RIGHT_READ, RIGHT_WRITE, SpawnHandleCopy, close, duplicate, program,
    spawn_many_copy, wait,
};

/// Step words handed to child copies of this probe.
const CHILD_READ_ONLY: u64 = 1;
const CHILD_WRITER: u64 = 2;
const CHILD_SECTOR: u64 = 8;

/// One full multi-sector request, in sectors and bytes.
const MULTI: usize = BLOCK_MAX_TRANSFER_SECTORS as usize;
const MULTI_BYTES: usize = BLOCK_SECTOR_BYTES * MULTI;
/// Where the multi-sector section writes: one request written as a whole
/// at `MULTI_BASE`, one written sector by sector right after it. The
/// host-side image check (`scripts/block-probe-image-check.py`) expects
/// exactly these bytes there after QEMU has exited.
const MULTI_BASE: u64 = 64;
/// Where a three-sector (partial) request is written; the sector after it
/// must stay zero, in the guest and on the host image.
const PARTIAL_BASE: u64 = 96;
const PARTIAL: usize = 3;

absd_user::multi_entry!(main);

fn pattern(lba: u64, index: usize) -> u8 {
    (lba as u8)
        .wrapping_mul(31)
        .wrapping_add((index as u8).wrapping_mul(7))
        | 1
}

/// The byte the multi-sector section expects at `index` of a buffer that
/// starts at sector `base`: the single-sector pattern with the top bit set,
/// so the two sections can never be confused.
fn multi_pattern(base: u64, index: usize) -> u8 {
    pattern(
        base + (index / BLOCK_SECTOR_BYTES) as u64,
        index % BLOCK_SECTOR_BYTES,
    ) | 0x80
}

fn run(console: Console, block: Block, step: u64) -> Result<(), &'static str> {
    let info = block.info().map_err(|_| "info")?;
    if info.sector_bytes != BLOCK_SECTOR_BYTES as u64 || info.sectors < 16 {
        return Err("geometry");
    }
    console
        .line(format_args!(
            "BLOCK PROBE step={step} sectors={}\n",
            info.sectors
        ))
        .map_err(|_| "write")?;

    // The append region on the still-zero image: cross a sector boundary,
    // then recover the exact length and content through a fresh scan.
    let mut ledger = Ledger::open(block).map_err(|_| "ledger open")?;
    if !ledger.is_empty() {
        return Err("ledger not empty");
    }
    let mut first = [0u8; 700];
    for (index, byte) in first.iter_mut().enumerate() {
        *byte = (index as u8).wrapping_mul(13) | 1;
    }
    ledger.append(&first).map_err(|_| "ledger append")?;
    ledger.flush().map_err(|_| "ledger flush")?;
    let second = b"second append after the barrier";
    ledger.append(second).map_err(|_| "ledger append 2")?;
    let expected_length = (first.len() + second.len()) as u64;
    if ledger.len() != expected_length {
        return Err("ledger length");
    }
    let reopened = Ledger::open(block).map_err(|_| "ledger reopen")?;
    if reopened.len() != expected_length {
        return Err("ledger recovered length");
    }
    let mut read = [0u8; 731];
    if reopened.read_at(0, &mut read).map_err(|_| "ledger read")? != read.len()
        || read[..700] != first
        || &read[700..] != second
    {
        return Err("ledger content");
    }
    if reopened
        .read_at(expected_length, &mut read)
        .map_err(|_| "ledger tail read")?
        != 0
    {
        return Err("ledger past end");
    }
    console
        .line(format_args!("LEDGER EXTENT OK bytes={expected_length}\n"))
        .map_err(|_| "write")?;

    // Raw sector transfers at the far end of the device.
    let base = info.sectors - 4;
    let mut sector = [0u8; BLOCK_SECTOR_BYTES];
    for lba in base..info.sectors {
        for (index, byte) in sector.iter_mut().enumerate() {
            *byte = pattern(lba, index);
        }
        block
            .write_sector(lba, &sector)
            .map_err(|_| "write sector")?;
    }
    for lba in base..info.sectors {
        block
            .read_sector(lba, &mut sector)
            .map_err(|_| "read sector")?;
        if sector
            .iter()
            .enumerate()
            .any(|(index, byte)| *byte != pattern(lba, index))
        {
            return Err("sector content");
        }
    }
    console
        .line(format_args!("BLOCK READ WRITE OK\n"))
        .map_err(|_| "write")?;
    block.flush().map_err(|_| "flush")?;
    console
        .line(format_args!("BLOCK FLUSH OK\n"))
        .map_err(|_| "write")?;

    // One request, several sectors. A full request is written whole and
    // read back whole, then cross-checked sector by sector through the
    // single-sector path; the next span is written sector by sector and
    // read back in one request. Both paths must agree on every byte, and
    // partial requests (one and three sectors) must see the same bytes.
    let mut page = [0u8; MULTI_BYTES];
    for (index, byte) in page.iter_mut().enumerate() {
        *byte = multi_pattern(MULTI_BASE, index);
    }
    block
        .write_sectors(MULTI_BASE, &page)
        .map_err(|_| "write sectors")?;
    let mut back = [0u8; MULTI_BYTES];
    block
        .read_sectors(MULTI_BASE, &mut back)
        .map_err(|_| "read sectors")?;
    if back != page {
        return Err("sectors content");
    }
    for index in 0..MULTI {
        block
            .read_sector(MULTI_BASE + index as u64, &mut sector)
            .map_err(|_| "read sector after multi write")?;
        if sector != page[index * BLOCK_SECTOR_BYTES..(index + 1) * BLOCK_SECTOR_BYTES] {
            return Err("sectors cross-check");
        }
    }
    let second_base = MULTI_BASE + MULTI as u64;
    for index in 0..MULTI {
        for (offset, byte) in sector.iter_mut().enumerate() {
            *byte = multi_pattern(second_base, index * BLOCK_SECTOR_BYTES + offset);
        }
        block
            .write_sector(second_base + index as u64, &sector)
            .map_err(|_| "write sector before multi read")?;
    }
    block
        .read_sectors(second_base, &mut back)
        .map_err(|_| "read sectors after single writes")?;
    if back
        .iter()
        .enumerate()
        .any(|(index, byte)| *byte != multi_pattern(second_base, index))
    {
        return Err("sectors after single writes");
    }
    back.fill(0);
    block
        .read_sectors(MULTI_BASE + 2, &mut back[..3 * BLOCK_SECTOR_BYTES])
        .map_err(|_| "read three sectors")?;
    if back[..3 * BLOCK_SECTOR_BYTES] != page[2 * BLOCK_SECTOR_BYTES..5 * BLOCK_SECTOR_BYTES] {
        return Err("three sectors content");
    }
    block
        .read_sectors(
            MULTI_BASE + MULTI as u64 - 1,
            &mut back[..BLOCK_SECTOR_BYTES],
        )
        .map_err(|_| "read one sector")?;
    if back[..BLOCK_SECTOR_BYTES] != page[(MULTI - 1) * BLOCK_SECTOR_BYTES..] {
        return Err("one sector content");
    }
    // A partial request as a write: three sectors land, the fourth stays
    // zero (a count one too high would put stale staging bytes there).
    let mut partial = [0u8; PARTIAL * BLOCK_SECTOR_BYTES];
    for (index, byte) in partial.iter_mut().enumerate() {
        *byte = multi_pattern(PARTIAL_BASE, index);
    }
    block
        .write_sectors(PARTIAL_BASE, &partial)
        .map_err(|_| "write three sectors")?;
    block
        .read_sectors(
            PARTIAL_BASE,
            &mut back[..(PARTIAL + 1) * BLOCK_SECTOR_BYTES],
        )
        .map_err(|_| "read after partial write")?;
    if back[..PARTIAL * BLOCK_SECTOR_BYTES] != partial
        || back[PARTIAL * BLOCK_SECTOR_BYTES..(PARTIAL + 1) * BLOCK_SECTOR_BYTES]
            .iter()
            .any(|byte| *byte != 0)
    {
        return Err("partial write extent");
    }
    console
        .line(format_args!("BLOCK MULTI SECTOR OK sectors={MULTI}\n"))
        .map_err(|_| "write")?;

    // Multi-sector refusals: an empty request, one past the bound, a span
    // that would straddle the device's end, an unrepresentable span, a
    // buffer that is not whole sectors, and a read-only copy. The refused
    // straddling write must leave the tail sectors exactly as written.
    let mut oversize = [0u8; MULTI_BYTES + BLOCK_SECTOR_BYTES];
    if block.read_sectors(MULTI_BASE, &mut back[..0]) != Err(Error::Invalid)
        || block.read_sectors(MULTI_BASE, &mut oversize) != Err(Error::Invalid)
        || block.write_sectors(MULTI_BASE, &oversize) != Err(Error::Invalid)
        || block.write_sectors(info.sectors - 4, &page) != Err(Error::Invalid)
        || block.read_sectors(info.sectors - 4, &mut back) != Err(Error::Invalid)
        || block.read_sectors(u64::MAX - 2, &mut back) != Err(Error::Invalid)
        || block.read_sectors(MULTI_BASE, &mut back[..BLOCK_SECTOR_BYTES + 1])
            != Err(Error::Invalid)
        || block.read_sectors(info.sectors - MULTI as u64 + 1, &mut back) != Err(Error::Invalid)
    {
        return Err("multi range");
    }
    // The exact fit at the device's end is accepted and sees the tail
    // pattern after four still-zero sectors.
    block
        .read_sectors(info.sectors - MULTI as u64, &mut back)
        .map_err(|_| "read exact fit at end")?;
    if back.iter().enumerate().any(|(index, byte)| {
        let lba = info.sectors - MULTI as u64 + (index / BLOCK_SECTOR_BYTES) as u64;
        let expected = if lba < base {
            0
        } else {
            pattern(lba, index % BLOCK_SECTOR_BYTES)
        };
        *byte != expected
    }) {
        return Err("exact fit content");
    }
    for lba in base..info.sectors {
        block
            .read_sector(lba, &mut sector)
            .map_err(|_| "read tail after refused span")?;
        if sector
            .iter()
            .enumerate()
            .any(|(index, byte)| *byte != pattern(lba, index))
        {
            return Err("refused span touched the device");
        }
    }
    let reader = Block::from_raw(duplicate(block.raw(), RIGHT_READ).map_err(|_| "narrow multi")?);
    if reader.write_sectors(MULTI_BASE, &page) != Err(Error::Rights)
        || reader.read_sectors(MULTI_BASE, &mut back).is_err()
        || back != page
    {
        return Err("multi rights");
    }
    close(reader.raw()).map_err(|_| "close narrow multi")?;
    console
        .line(format_args!("BLOCK MULTI REFUSALS OK\n"))
        .map_err(|_| "write")?;

    // Negative controls: the device's edge, rights, and impossible rights.
    if block.read_sector(info.sectors, &mut sector) != Err(Error::Invalid)
        || block.write_sector(u64::MAX, &sector) != Err(Error::Invalid)
    {
        return Err("range");
    }
    let reader = Block::from_raw(duplicate(block.raw(), RIGHT_READ).map_err(|_| "narrow")?);
    if reader.write_sector(base, &sector) != Err(Error::Rights)
        || reader.flush() != Err(Error::Rights)
        || reader.read_sector(base, &mut sector).is_err()
    {
        return Err("rights");
    }
    close(reader.raw()).map_err(|_| "close narrow")?;
    if duplicate(block.raw(), RIGHT_KILL) != Err(Error::Rights) {
        return Err("kill right");
    }
    console
        .line(format_args!("BLOCK REFUSALS OK\n"))
        .map_err(|_| "write")?;

    // Two processes and one device. The kernel enforces rights on each
    // copied handle, nothing more: a read-only copy cannot write, a
    // write-capable copy can. Which processes hold a write-capable copy is
    // init's exclusive-writer policy (one durable worker at a time), not a kernel
    // guarantee, and this records that boundary exactly.
    if spawn_child(console, block, RIGHT_READ, CHILD_READ_ONLY)? != Outcome::Exited(0) {
        return Err("read-only child");
    }
    for (index, byte) in sector.iter_mut().enumerate() {
        *byte = pattern(CHILD_SECTOR, index);
    }
    block
        .write_sector(CHILD_SECTOR, &sector)
        .map_err(|_| "seed child sector")?;
    if spawn_child(console, block, RIGHT_READ | RIGHT_WRITE, CHILD_WRITER)? != Outcome::Exited(0) {
        return Err("writer child");
    }
    block
        .read_sector(CHILD_SECTOR, &mut sector)
        .map_err(|_| "read child sector")?;
    if sector.iter().any(|byte| *byte != 0x5a) {
        return Err("writer child sector");
    }
    console
        .line(format_args!(
            "BLOCK SINGLE WRITER policy=init kernel_enforced=rights-only\n"
        ))
        .map_err(|_| "write")?;
    console
        .line(format_args!("BLOCK WRITER RIGHTS OK\n"))
        .map_err(|_| "write")?;
    Ok(())
}

/// Runs a copy of this probe with a copied device handle and a step cell.
fn spawn_child(
    console: Console,
    block: Block,
    rights: u64,
    step: u64,
) -> Result<Outcome, &'static str> {
    let input = Pipe::create().map_err(|_| "child input pipe")?;
    let cell = Cell::create(step).map_err(|_| "child step cell")?;
    let copies = [
        SpawnHandleCopy::new(input.raw(), RIGHT_READ),
        SpawnHandleCopy::new(block.raw(), rights),
        SpawnHandleCopy::new(cell.raw(), RIGHT_READ),
        SpawnHandleCopy::console(console.raw(), RIGHT_WRITE),
    ];
    let child = spawn_many_copy(program::BLOCK_PROBE, &copies).map_err(|_| "child spawn")?;
    close(input.raw()).map_err(|_| "child input close")?;
    let outcome = wait(Some(child)).map_err(|_| "child wait")?;
    close(cell.raw()).map_err(|_| "child cell close")?;
    Ok(outcome)
}

/// A child copy: prove what its copied handle can and cannot do.
fn run_child(block: Block, step: u64) -> i32 {
    let mut sector = [0x5au8; BLOCK_SECTOR_BYTES];
    match step {
        CHILD_READ_ONLY => {
            let refused = block.write_sector(CHILD_SECTOR, &sector) == Err(Error::Rights)
                && block.flush() == Err(Error::Rights)
                && block.read_sector(CHILD_SECTOR, &mut sector).is_ok();
            if refused { 0 } else { 3 }
        }
        CHILD_WRITER => {
            if block.write_sector(CHILD_SECTOR, &sector).is_ok() && block.flush().is_ok() {
                0
            } else {
                4
            }
        }
        _ => 5,
    }
}

fn main(start: MultiStart) -> i32 {
    let console = start.console;
    if start.handles.len() != 4 {
        return 90;
    }
    let block = Block::from_raw(start.handles[1]);
    let step = match Cell::from_raw(start.handles[2]).read() {
        Ok((_, value)) => value,
        Err(_) => return 91,
    };
    if step == CHILD_READ_ONLY || step == CHILD_WRITER {
        return run_child(block, step);
    }
    match run(console, block, step) {
        Ok(()) => 0,
        Err(step) => {
            let _ = console.line(format_args!("block-probe: FAILED at {step}\n"));
            92
        }
    }
}
