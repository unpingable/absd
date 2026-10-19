//! Opt-in external fixture; parent-local kill/wait authority is its administration boundary.
#![no_std]
#![no_main]
#[path = "../reservation_fixture.rs"]
mod fixture;
use absd_abi::syscall::SpawnHandleCopy;
use absd_user::{
    Cell, Child, Error, MultiStart, Outcome, Pipe, close, cprintln, frame_stats, info, kill, map,
    program, resource_census, unmap, wait_timeout,
};
use fixture::*;
absd_user::multi_entry!(main);
fn main(start: MultiStart<'_>) -> i32 {
    // Drain the external launcher's input so it can supervise output normally.
    let [input, _] = start.handles else {
        return 90;
    };
    let mut bytes = [0u8; 128];
    loop {
        match Pipe::from_raw(*input).read_once(&mut bytes) {
            Ok(0) => break,
            Ok(_) => {}
            Err(_) => return 91,
        }
    }
    match run(start) {
        Ok(()) => 0,
        Err(step) => {
            let _ = cprintln!(start.console, "RESERVATION FAILED step={}", step);
            94
        }
    }
}
static ACTOR_IMAGE: &[u8] = include_bytes!(env!("ABSD_RESERVATION_ACTOR_EMBED"));

fn image_call(
    number: u64,
    image: &[u8],
    copies: &[SpawnHandleCopy],
    total: u64,
    flags: u64,
) -> i64 {
    let request = absd_abi::syscall::SpawnImageRequest {
        image: image.as_ptr() as u64,
        image_bytes: image.len() as u64,
        handles: copies.as_ptr() as u64,
        handle_count: copies.len() as u64,
    };
    call(number, &request as *const _ as u64, flags, total)
}
fn actor(protected: bool, total: u64, cell: Cell) -> Result<Child, Error> {
    let copies = [SpawnHandleCopy::new(
        cell.raw(),
        absd_abi::syscall::RIGHT_READ | absd_abi::syscall::RIGHT_WRITE,
    )];
    if protected {
        let raw = image_call(SPAWN_IMAGE, ACTOR_IMAGE, &copies, total, 0);
        if raw < 0 {
            Err(Error::Unknown(raw))
        } else {
            Ok(Child::from_raw(raw as u64))
        }
    } else {
        absd_user::spawn_image(ACTOR_IMAGE, &copies, 0)
    }
}
fn catalog_actor(total: u64, cell: Cell) -> Result<Child, Error> {
    let raw = call(SPAWN, program::OWNER_1, total, cell.raw());
    if raw < 0 {
        Err(Error::Unknown(raw))
    } else {
        Ok(Child::from_raw(raw as u64))
    }
}

fn abort_controls(
    start: MultiStart<'_>,
    baseline: absd_abi::syscall::ResourceCensus,
) -> Result<(), &'static str> {
    use absd_abi::syscall::{RIGHT_READ, RIGHT_WRITE};
    if call(QUERY, 3, 0, 0) != 3 {
        return Err("image qualification profile");
    }
    let cell = Cell::create(4).map_err(|_| "abort cell")?;
    let anchor = actor(true, 64, cell).map_err(|_| "anchor")?;
    let anchor_pid = info(Some(anchor)).map_err(|_| "anchor identity")?.pid;
    until(cell, 40).map_err(|_| "anchor ready")?;
    kill(anchor).map_err(|_| "anchor kill")?;
    wait_timeout(Some(anchor), 1000).map_err(|_| "anchor reap")?;
    set(cell, 4).map_err(|_| "abort cell reset")?;
    let copies = [
        SpawnHandleCopy::new(cell.raw(), RIGHT_READ | RIGHT_WRITE),
        SpawnHandleCopy::new(cell.raw(), RIGHT_READ),
        SpawnHandleCopy::console(start.console.raw(), RIGHT_WRITE),
    ];
    let witness_before = cell.read().map_err(|_| "witness before")?;
    let live = image_call(SPAWN_IMAGE, ACTOR_IMAGE, &copies, 64, 0);
    if live < 0
        || wait_timeout(Some(Child::from_raw(live as u64)), 1000).map_err(|_| "witness wait")?
            != Outcome::Exited(0)
    {
        return Err("execution witness activation");
    }
    let witness_after = cell.read().map_err(|_| "witness after")?;
    if witness_after == witness_before || witness_after.1 != 80 {
        return Err("execution witness did not change");
    }
    set(cell, 4).map_err(|_| "witness reset")?;
    let before = resource_census().map_err(|_| "abort census")?;
    let cell_before = cell.read().map_err(|_| "abort cell before")?;
    let pipe_before = absd_user::pipe_info(start.console.raw()).map_err(|_| "abort pipe")?;
    for _ in 0..64 {
        if image_call(ABORT_IMAGE, ACTOR_IMAGE, &copies, 64, 0) != -11 {
            return Err("built abort result");
        }
        if resource_census().map_err(|_| "abort after")? != before
            || call(QUERY, 1, 0, 0) != 192
            || cell.read().map_err(|_| "abort child ran")? != cell_before
            || absd_user::pipe_info(start.console.raw())
                .map_err(|_| "abort pipe after")?
                .writers
                != pipe_before.writers
        {
            return Err("built abort leaked or activated");
        }
    }
    let next = actor(true, 64, cell).map_err(|_| "abort next child")?;
    if info(Some(next)).map_err(|_| "abort next identity")?.pid != anchor_pid + 2 {
        return Err("abort consumed PID");
    }
    kill(next).map_err(|_| "abort next kill")?;
    wait_timeout(Some(next), 1000).map_err(|_| "abort next reap")?;
    // Existing quota failure injection must refuse rather than withdraw backing.
    if image_call(
        absd_abi::syscall::SYS_SPAWN_IMAGE,
        ACTOR_IMAGE,
        &copies,
        1,
        0,
    ) != -22
        || resource_census().map_err(|_| "quota census")? != before
        || call(QUERY, 1, 0, 0) != 192
    {
        return Err("quota withdrew reservation");
    }
    if image_call(SPAWN_IMAGE, &[0u8; 64], &copies, 64, 0) != -8 {
        return Err("borrowed bad image");
    }
    if call(SPAWN_IMAGE, 1, 0, 64) != -14 {
        return Err("borrowed bad descriptor");
    }
    close(cell.raw()).map_err(|_| "abort close")?;
    if resource_census().map_err(|_| "abort final")? != baseline || call(QUERY, 1, 0, 0) != 192 {
        return Err("abort final return");
    }
    cprintln!(start.console,"IMAGE ABORT OK cycles=64 frames_idle_objects_pid_return=true child_not_activated=true execution_witness_verified=true quota_refused=-22").map_err(|_|"abort output")?;
    Ok(())
}

fn run(start: MultiStart<'_>) -> Result<(), &'static str> {
    let warm = map(1).map_err(|_| "warm")?;
    unmap(warm, 1).map_err(|_| "warm unmap")?;
    let mut samples = [0u64; 32];
    for sample in &mut samples {
        let t = ticks();
        let p = map(64).map_err(|_| "map timing")?;
        *sample = ticks() - t;
        unmap(p, 64).map_err(|_| "timing unmap")?;
    }
    samples.sort_unstable();
    cprintln!(
        start.console,
        "MAP64 COST guest_tsc_median={} min={} max={} samples=32",
        samples[16],
        samples[0],
        samples[31]
    )
    .map_err(|_| "timing output")?;
    let baseline = resource_census().map_err(|_| "baseline")?;
    let owned = call(QUERY, 0, 0, 0);
    let admission = call(ADMIT, (owned.max(0) + 192) as u64, 0, 0);
    let protected = admission == 0;
    if !protected && admission != -38 {
        return Err("supervisor admission");
    }
    cprintln!(
        start.console,
        "MODE protected={} supervisor_idle={} borrowed_image=true",
        protected,
        if protected { 192 } else { 0 }
    )
    .map_err(|_| "mode")?;
    if protected {
        abort_controls(start, baseline)?;
        if call(ADMIT, 65536, 0, 0) != -22 {
            return Err("duplicate admission");
        }
        let idle = call(QUERY, 1, 0, 0);
        let cell = Cell::create(4).map_err(|_| "failure cell")?;
        let before = resource_census().map_err(|_| "failure baseline")?;
        let mut failures = 0;
        for total in 1..=64 {
            match actor(true, total, cell) {
                Err(Error::Unknown(-12)) => {
                    if resource_census().map_err(|_| "failed census")? != before
                        || call(QUERY, 1, 0, 0) != idle
                    {
                        return Err("initialization leak");
                    }
                    failures += 1;
                }
                Ok(child) => {
                    kill(child).map_err(|_| "init kill")?;
                    wait_timeout(Some(child), 1000).map_err(|_| "init reap")?;
                    break;
                }
                Err(_) => return Err("failed init semantics"),
            }
        }
        if failures == 0 || failures == 64 {
            return Err("initialization sweep");
        }
        close(cell.raw()).map_err(|_| "failure cell close")?;
        cprintln!(
            start.console,
            "INITIALIZATION REFUSALS OK count={} exact_return=true",
            failures
        )
        .map_err(|_| "init output")?;
        let before = resource_census().map_err(|_| "negative baseline")?;
        if call(SPAWN, program::OWNER_2, 64, 0) != -22
            || resource_census().map_err(|_| "bad image census")? != before
            || call(QUERY, 1, 0, 0) != 192
        {
            return Err("bad image reservation leak");
        }
        if call(SPAWN, program::OWNER_1, 64, 0x12345678) != -9 {
            return Err("invalid transfer handle");
        }
        if call(QUERY, 0, 1, 0) != -22 || call(ADMIT, 1, 1, 0) != -22 {
            return Err("experimental arguments");
        }
        let cell = Cell::create(6).map_err(|_| "rights cell")?;
        let raw = call(
            SPAWN,
            program::OWNER_1 | absd_abi::syscall::SPAWN_NO_SPAWN,
            64,
            cell.raw(),
        );
        if raw < 0
            || wait_timeout(Some(Child::from_raw(raw as u64)), 1000).map_err(|_| "rights wait")?
                != Outcome::Exited(0)
        {
            return Err("spawn permission");
        }
        let copies = [SpawnHandleCopy::new(
            cell.raw(),
            absd_abi::syscall::RIGHT_READ | absd_abi::syscall::RIGHT_WRITE,
        )];
        let raw = image_call(
            SPAWN_IMAGE,
            ACTOR_IMAGE,
            &copies,
            64,
            absd_abi::syscall::SPAWN_NO_SPAWN,
        );
        if raw < 0
            || wait_timeout(Some(Child::from_raw(raw as u64)), 1000)
                .map_err(|_| "image rights wait")?
                != Outcome::Exited(0)
        {
            return Err("image spawn permission");
        }
        close(cell.raw()).map_err(|_| "rights close")?;
        cprintln!(
            start.console,
            "NEGATIVE OK bad_image=-22 bad_handle=-9 bad_arguments=-22 no_spawn=-1 image_no_spawn=-1"
        )
        .map_err(|_| "negative output")?;
        for cycle in 0..64 {
            let role = match cycle % 4 {
                0 => 3,
                1 => 4,
                2 => 5,
                _ => 7,
            };
            let cell = Cell::create(role).map_err(|_| "cycle cell")?;
            let child = if cycle == 0 {
                catalog_actor(64, cell)
            } else {
                actor(true, 64, cell)
            }
            .map_err(|_| "cycle admission")?;
            if role == 4 {
                until(cell, 40).map_err(|_| "cycle ready")?;
                kill(child).map_err(|_| "cycle kill")?;
            }
            let outcome = wait_timeout(Some(child), 1000).map_err(|_| "cycle wait")?;
            if !matches!(
                (role, outcome),
                (3, Outcome::Exited(0))
                    | (4, Outcome::Killed)
                    | (5, Outcome::Faulted { vector: 6, .. })
                    | (7, Outcome::Faulted { vector: 14, .. })
            ) {
                return Err("cycle outcome");
            }
            if info(Some(child)) != Err(Error::BadHandle) {
                return Err("stale handle");
            }
            close(cell.raw()).map_err(|_| "cycle close")?;
            if resource_census().map_err(|_| "cycle census")? != baseline
                || call(QUERY, 1, 0, 0) != 192
            {
                return Err("cycle leak");
            }
        }
        cprintln!(
            start.console,
            "LIFECYCLE OK cycles=64 exit_kill_fault=true stale_handles_refused=true stack_exhaustion_vector=14"
        )
        .map_err(|_| "cycles output")?;
    }
    let ac = Cell::create(1).map_err(|_| "A cell")?;
    let bc = Cell::create(2).map_err(|_| "B cell")?;
    let a = actor(protected, 640, ac).map_err(|_| "A spawn")?;
    until(ac, 10).map_err(|_| "A ready")?;
    let b = actor(false, 0, bc).map_err(|_| "B spawn")?;
    until(bc, 20).map_err(|_| "B initial ready")?;
    let mut fillers = [None; 16];
    let mut filler_count = 0;
    loop {
        match absd_user::spawn_with(program::SLEEPER, 0, 100000) {
            Ok(child) if filler_count < fillers.len() => {
                fillers[filler_count] = Some(child);
                filler_count += 1;
            }
            Err(Error::Again) => break,
            _ => return Err("process pressure refusal"),
        }
    }
    if filler_count == 0 || resource_census().map_err(|_| "full census")?.processes != 16 {
        return Err("process pressure occupancy");
    }
    let full = resource_census().map_err(|_| "full before")?;
    if protected && call(SPAWN, program::OWNER_1, 640, ac.raw()) != -11 {
        return Err("full reserved constructor");
    }
    if resource_census().map_err(|_| "full after")? != full {
        return Err("full constructor leaked");
    }
    cprintln!(start.console,"SLOT PRESSURE OK occupied=16 fillers={} refusal=-11 existing_commitments_preconstructed=true",filler_count).map_err(|_|"slot output")?;
    set(bc, 200).map_err(|_| "B exhaustion go")?;
    until(bc, 21).map_err(|_| "B exhaustion")?;
    let bpages = bc.read().map_err(|_| "B report")?.1 >> 16;
    cprintln!(
        start.console,
        "B EXHAUSTED pages={} refusal=-12 retries=3 competing_admit={}",
        bpages,
        if protected { -12 } else { -38 }
    )
    .map_err(|_| "B output")?;
    if protected {
        let free = frame_stats().map_err(|_| "pressure stats")?.free_frames;
        let idle = call(QUERY, 1, 0, 0);
        if free != idle as u64 {
            return Err("B left ordinary capacity");
        }
        let before = resource_census().map_err(|_| "full pressure census")?;
        if call(SPAWN, program::OWNER_1, 640, ac.raw()) != -11
            || resource_census().map_err(|_| "admission after")? != before
            || call(QUERY, 1, 0, 0) != idle
        {
            return Err("full admission changed backing");
        }
    }
    set(ac, 100).map_err(|_| "A go")?;
    until(ac, if protected { 11 } else { 12 }).map_err(|_| "A result")?;
    if protected {
        cprintln!(start.console,"A CAPACITY OK total=640 used=640 pages=512 stack_descent=12 recycle=512 cap_refusal=-12").map_err(|_|"A output")?;
    } else {
        cprintln!(start.console, "A REFUSED -12").map_err(|_| "A refusal output")?;
    }
    let pressure_start = ticks();
    let memory = map(64);
    let pressure_cycles = ticks() - pressure_start;
    if protected {
        let p = memory.map_err(|_| "supervisor headroom")?;
        touch(p, 64);
        unmap(p, 64).map_err(|_| "supervisor release")?;
        if info(Some(b)).is_err() {
            return Err("supervisor observation");
        }
        cprintln!(
            start.console,
            "SUPERVISOR HEADROOM OK map=64 observe=true kill_wait=true map64_tsc={}",
            pressure_cycles
        )
        .map_err(|_| "supervisor output")?;
    } else if memory != Err(Error::NoMemory) {
        return Err("baseline supervisor unexpectedly backed");
    } else if wait_timeout(Some(a), 1000).map_err(|_| "baseline A reap")? != Outcome::Exited(12) {
        return Err("baseline A outcome");
    }
    // Reclaim a real slot while all other slots remain occupied. Its actual
    // frames return to the ordinary pool; B must exhaust those too before
    // testing refusal for unavailable backing rather than unavailable slots.
    let filler = fillers[filler_count - 1].take().ok_or("missing filler")?;
    kill(filler).map_err(|_| "filler kill")?;
    if wait_timeout(Some(filler), 1000).map_err(|_| "filler reap")? != Outcome::Killed {
        return Err("filler outcome");
    }
    set(bc, 220).map_err(|_| "B reexhaust go")?;
    until(bc, 22).map_err(|_| "B reexhaust")?;
    cprintln!(
        start.console,
        "B REEXHAUSTED pages={} refusal=-12 retries=3 returned_slot_reused=false",
        bc.read().map_err(|_| "B final pages")?.1 >> 16
    )
    .map_err(|_| "B reexhaust output")?;
    if protected {
        let free = frame_stats()
            .map_err(|_| "second pressure stats")?
            .free_frames;
        let idle = call(QUERY, 1, 0, 0);
        let before = resource_census().map_err(|_| "admission census")?;
        if free != idle as u64
            || call(SPAWN, program::OWNER_1, 640, ac.raw()) != -12
            || resource_census().map_err(|_| "admission after")? != before
            || call(QUERY, 1, 0, 0) != idle
        {
            return Err("unbacked admission");
        }
        cprintln!(
            start.console,
            "PRESSURE OK free={} idle_reserved={} competing_spawn=-12 slot_available=true",
            free,
            idle
        )
        .map_err(|_| "pressure output")?;
        set(ac, 300).map_err(|_| "A release")?;
    }
    for filler in fillers.into_iter().flatten() {
        kill(filler).map_err(|_| "remaining filler kill")?;
        if wait_timeout(Some(filler), 1000).map_err(|_| "remaining filler reap")? != Outcome::Killed
        {
            return Err("remaining filler outcome");
        }
    }
    kill(b).map_err(|_| "B kill")?;
    if wait_timeout(Some(b), 1000).map_err(|_| "B reap")? != Outcome::Killed {
        return Err("B outcome");
    }
    if protected && wait_timeout(Some(a), 1000).map_err(|_| "A reap")? != Outcome::Exited(0) {
        return Err("A outcome");
    }
    close(ac.raw()).map_err(|_| "A close")?;
    close(bc.raw()).map_err(|_| "B close")?;
    if resource_census().map_err(|_| "final census")? != baseline {
        return Err("final resource return");
    }
    if protected && call(QUERY, 1, 0, 0) != 192 {
        return Err("final idle return");
    }
    cprintln!(
        start.console,
        "RESERVATION RESULT protected={} exact_return=true",
        protected
    )
    .map_err(|_| "result")?;
    Ok(())
}
