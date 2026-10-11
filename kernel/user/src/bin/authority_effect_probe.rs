//! Direct Cell effect/refusal, stale-slot, partial-copy and capacity regression.
#![no_std]
#![no_main]
use absd_user::{
    Cell, Error, MultiStart, Pipe, RIGHT_READ, RIGHT_WRITE, SpawnHandleCopy, close, duplicate,
    resource_census, spawn_image,
};
absd_user::multi_entry!(main);
const TICKS: u64 = 5_000;
static CHILD: &[u8] = include_bytes!(env!("ABSD_AUTHORITY_EFFECT_CHILD_EMBED"));
fn need(ok: bool, step: &'static str) -> Result<(), &'static str> {
    if ok { Ok(()) } else { Err(step) }
}
fn say(start: MultiStart<'_>, text: &str) -> Result<(), &'static str> {
    start.console.write_str(text).map_err(|_| "output")?;
    start.console.write_str("\n").map_err(|_| "output")
}
fn run(start: MultiStart<'_>) -> Result<(), &'static str> {
    let [input, output] = start.handles else {
        return Err("startup");
    };
    need(*output == start.console.raw(), "console")?;
    need(
        Pipe::from_raw(*input).read_timeout(&mut [0u8; 1], TICKS) == Ok(0),
        "startup-eof",
    )?;
    close(*input).map_err(|_| "startup-close")?;
    let base = resource_census().map_err(|_| "baseline")?;
    let cell = Cell::create(42).map_err(|_| "create")?;
    let ro = duplicate(cell.raw(), RIGHT_READ).map_err(|_| "ro")?;
    let before = cell.read().map_err(|_| "before")?;
    // Must detect a mutant that returns precisely Rights *after mutation*.
    need(
        Cell::from_raw(ro).transition(0, 99) == Err(Error::Rights),
        "denied-status",
    )?;
    need(cell.read() == Ok(before), "denied-effect")?;
    need(
        cell.transition(7, 99) == Err(Error::Stale) && cell.read() == Ok(before),
        "stale-effect",
    )?;
    say(
        start,
        "COMPOSE denied-write status=Rights target-version=0 value=42 unchanged=true",
    )?;
    say(start, "COMPOSE stale-version status=Stale target=unchanged")?;
    let during = resource_census().map_err(|_| "during")?;
    let copies = [
        SpawnHandleCopy::new(cell.raw(), RIGHT_READ),
        SpawnHandleCopy::new(ro, RIGHT_READ | RIGHT_WRITE),
    ];
    need(
        spawn_image(CHILD, &copies, 0) == Err(Error::Rights),
        "partial-grant-status",
    )?;
    need(
        duplicate(ro, RIGHT_READ | RIGHT_WRITE) == Err(Error::Rights),
        "partial-grant-ro-rights",
    )?;
    need(
        Cell::from_raw(ro).transition(0, 88) == Err(Error::Rights) && cell.read() == Ok(before),
        "partial-grant-ro-effect",
    )?;
    let rw =
        duplicate(cell.raw(), RIGHT_READ | RIGHT_WRITE).map_err(|_| "partial-grant-rw-rights")?;
    close(rw).map_err(|_| "partial-grant-rw-close")?;
    need(
        resource_census() == Ok(during)
            && cell.read() == Ok(before)
            && Cell::from_raw(ro).read() == Ok(before),
        "partial-grant-effect",
    )?;
    say(
        start,
        "COMPOSE partial-grant status=Rights source-rights=unchanged census=equal",
    )?;
    close(ro).map_err(|_| "ro-close")?;
    let stale = cell.raw();
    close(stale).map_err(|_| "cell-close")?;
    let replacement = Cell::create(77).map_err(|_| "replacement")?;
    need(
        (stale & 255) == (replacement.raw() & 255) && stale != replacement.raw(),
        "same-slot",
    )?;
    need(
        Cell::from_raw(stale).transition(0, 99) == Err(Error::BadHandle)
            && replacement.read() == Ok((0, 77)),
        "aba-effect",
    )?;
    close(replacement.raw()).map_err(|_| "replacement-close")?;
    need(resource_census() == Ok(base), "direct-census")?;
    say(
        start,
        "COMPOSE stale-token same-slot=true replacement-value=77 unchanged=true census=equal",
    )?;
    let capacity_cell = Cell::create(33).map_err(|_| "capacity-cell")?;
    let mut held = [0u64; 64];
    let mut count = 0;
    loop {
        match duplicate(capacity_cell.raw(), RIGHT_READ) {
            Ok(h) => {
                need(count < held.len(), "capacity-bound")?;
                held[count] = h;
                count += 1;
            }
            Err(Error::TooManyHandles) => break,
            Err(_) => return Err("capacity-unexpected"),
        }
    }
    need(
        count == 62 && capacity_cell.read() == Ok((0, 33)),
        "capacity-state",
    )?;
    need(
        duplicate(capacity_cell.raw(), RIGHT_READ) == Err(Error::TooManyHandles),
        "capacity-repeat",
    )?;
    for h in &held[..count] {
        close(*h).map_err(|_| "capacity-close")?;
    }
    close(capacity_cell.raw()).map_err(|_| "capacity-cell-close")?;
    need(resource_census() == Ok(base), "capacity-census")?;
    say(
        start,
        "COMPOSE handle-limit repeated=TooManyHandles target=unchanged reclaimed=exact",
    )?;
    need(resource_census() == Ok(base), "final-census")?;
    say(start, "COMPOSE effects verified=true final-census=equal")?;
    say(start, "COMPOSE OK")
}
fn main(start: MultiStart<'_>) -> i32 {
    match run(start) {
        Ok(()) => 0,
        Err(stage) => {
            let _ = absd_user::cprintln!(start.console, "COMPOSE FAILED stage={stage}");
            1
        }
    }
}
