//! One real Cell, exercised across ordinary ring-3 processes. No new ABI.
#![no_std]
#![no_main]

use absd_abi::syscall::ResourceCensus;
use absd_user::{
    Cell, Child, Console, MultiStart, Outcome, Pipe, RIGHT_READ, RIGHT_WRITE, SpawnHandleCopy,
    close, duplicate, kill, resource_census, spawn_image, wait_timeout,
};

absd_user::multi_entry!(main);

const TICKS: u64 = 5_000;
const VALUE: u64 = 0xc311_0000_0000_0042;
static ACTOR: &[u8] = include_bytes!(env!("ABSD_CAPABILITY_ACTOR_EMBED"));

fn need(ok: bool, step: &'static str) -> Result<(), &'static str> {
    if ok { Ok(()) } else { Err(step) }
}

fn main(start: MultiStart<'_>) -> i32 {
    match run(start) {
        Ok(()) => 0,
        Err(step) => {
            let _ = absd_user::cprintln!(start.console, "CAP FAILED stage={step}");
            1
        }
    }
}

fn read(pipe: Pipe, bytes: &mut [u8]) -> Result<(), &'static str> {
    let mut offset = 0;
    while offset < bytes.len() {
        let count = pipe
            .read_timeout(&mut bytes[offset..], TICKS)
            .map_err(|_| "report-read")?;
        need(count > 0, "report-short")?;
        offset += count;
    }
    Ok(())
}

fn spawn_actor(
    role: u64,
    token: u64,
    extras: &[SpawnHandleCopy],
) -> Result<(Child, Pipe), &'static str> {
    let control = Pipe::create().map_err(|_| "control-create")?;
    let report = Pipe::create().map_err(|_| "report-create")?;
    let mut copies = [SpawnHandleCopy::new(0, 0); 4];
    copies[0] = SpawnHandleCopy::new(control.raw(), RIGHT_READ);
    copies[1] = SpawnHandleCopy::new(report.raw(), RIGHT_WRITE);
    copies[2..2 + extras.len()].copy_from_slice(extras);
    // Leave spawn permission enabled in every actor, including C.
    let child = spawn_image(ACTOR, &copies[..2 + extras.len()], 0).map_err(|_| "actor-spawn")?;
    let mut input = [0u8; 32];
    input[..8].copy_from_slice(&role.to_le_bytes());
    input[8..16].copy_from_slice(&token.to_le_bytes());
    need(
        control.write_timeout(&input, TICKS) == Ok(input.len()),
        "control-write",
    )?;
    close(control.raw()).map_err(|_| "control-close")?;
    let reader = duplicate(report.raw(), RIGHT_READ).map_err(|_| "report-narrow")?;
    close(report.raw()).map_err(|_| "report-close-rw")?;
    Ok((child, Pipe::from_raw(reader)))
}

fn exited(child: Child, stage: &'static str) -> Result<(), &'static str> {
    need(
        wait_timeout(Some(child), TICKS) == Ok(Outcome::Exited(0)),
        stage,
    )
}

fn census_diagnostic(console: Console, stage: &'static str, side: &str, census: ResourceCensus) {
    // Snapshot first; logging must not change which counts are compared.
    let _ = absd_user::cprintln!(
        console,
        "CAP CENSUS stage={stage} side={side} processes={} handles={} pipes={} cells={} frames={}",
        census.processes,
        census.handles,
        census.pipes,
        census.cells,
        census.frames
    );
}

fn exact(base: ResourceCensus, console: Console, stage: &'static str) -> Result<(), &'static str> {
    let after = resource_census().map_err(|_| "census-read")?;
    if after != base {
        census_diagnostic(console, stage, "before", base);
        census_diagnostic(console, stage, "after", after);
        return Err(stage);
    }
    Ok(())
}

fn cell() -> Result<Cell, &'static str> {
    let cell = Cell::create(0).map_err(|_| "cell-create")?;
    need(cell.transition(0, VALUE) == Ok(1), "a-transition")?;
    need(cell.read() == Ok((1, VALUE)), "a-read")?;
    Ok(cell)
}

fn run(start: MultiStart<'_>) -> Result<(), &'static str> {
    let console = start.console;
    need(!ACTOR.is_empty(), "actor-embed")?;
    let [input, output] = start.handles else {
        return Err("startup-input");
    };
    need(*output == console.raw(), "startup-output")?;
    // Init closes its input writer asynchronously. Establish that boundary
    // before the exact baseline; never normalize a disappearing handle.
    need(
        Pipe::from_raw(*input).read_timeout(&mut [0u8; 1], TICKS) == Ok(0),
        "startup-input-eof",
    )?;
    close(*input).map_err(|_| "startup-input-close")?;
    let base = resource_census().map_err(|_| "baseline")?;
    let resource = cell()?;
    absd_user::cprintln!(console, "CAP A explicit-rw read=true transition=true")
        .map_err(|_| "output")?;

    let (b, report) = spawn_actor(1, resource.raw(), &[])?;
    exited(b, "b-authority-refusal")?;
    let mut ack = [0];
    read(report, &mut ack)?;
    need(
        ack == [1] && resource.read() == Ok((1, VALUE)),
        "b-unchanged",
    )?;
    close(report.raw()).map_err(|_| "b-report-close")?;
    absd_user::cprintln!(
        console,
        "CAP B raw-token=refused same-slot-rw-decoy=true state=unchanged"
    )
    .map_err(|_| "output")?;

    let (c, report) = spawn_actor(2, 0, &[SpawnHandleCopy::new(resource.raw(), RIGHT_READ)])?;
    exited(c, "c-attenuation")?;
    close(report.raw()).map_err(|_| "c-report-close")?;
    need(resource.read() == Ok((1, VALUE)), "c-unchanged")?;
    close(resource.raw()).map_err(|_| "a-close")?;
    exact(base, console, "a-b-c-census")?;
    absd_user::cprintln!(console, "CAP C read=true write=refused duplicate-rw=refused forward-rw=refused forward-ro=true spawn-enabled=true").map_err(|_| "output")?;
    absd_user::cprintln!(
        console,
        "CAP stale same-slot-reissue=true old-token=refused fresh-ro=true"
    )
    .map_err(|_| "output")?;

    for role in 3..=6 {
        let resource = cell()?;
        let gate = Pipe::create().map_err(|_| "gate-create")?;
        let (child, report) = spawn_actor(
            role,
            0,
            &[
                SpawnHandleCopy::new(resource.raw(), RIGHT_READ),
                SpawnHandleCopy::new(gate.raw(), RIGHT_READ),
            ],
        )?;
        close(resource.raw()).map_err(|_| "holder-a-close")?;
        if role != 3 {
            read(report, &mut ack)?;
            need(ack == [1], "holder-ready")?;
        }
        if role == 5 {
            kill(child).map_err(|_| "holder-kill")?;
            need(
                wait_timeout(Some(child), TICKS) == Ok(Outcome::Killed),
                "holder-killed-outcome",
            )?;
            close(gate.raw()).map_err(|_| "kill-gate-close")?;
        } else {
            close(gate.raw()).map_err(|_| "holder-gate-close")?;
            if role == 6 {
                need(
                    matches!(
                        wait_timeout(Some(child), TICKS),
                        Ok(Outcome::Faulted {
                            vector: 6,
                            error: 0,
                            ..
                        })
                    ),
                    "holder-fault-outcome",
                )?;
            } else {
                exited(child, "holder-exit-outcome")?;
                read(report, &mut ack)?;
                need(ack == [2], "holder-survived-close")?;
            }
        }
        close(report.raw()).map_err(|_| "holder-report-close")?;
        exact(base, console, "holder-cleanup-census")?;
        let description = match role {
            3 => "CAP close grant-survives=true final-holder-exit-census=equal",
            4 => "CAP normal-exit final-holder-census=equal",
            5 => "CAP kill final-holder-census=equal",
            _ => "CAP fault vector=6 final-holder-census=equal",
        };
        console.write_str(description).map_err(|_| "output")?;
        console.write_str("\n").map_err(|_| "output")?;
    }

    let (grantor, report) = spawn_actor(7, 0, &[])?;
    let mut pid = [0u8; 8];
    read(report, &mut pid)?;
    let leaf_pid = u64::from_le_bytes(pid);
    need(leaf_pid > 0, "leaf-identity")?;
    exited(grantor, "grantor-exit")?;
    read(report, &mut ack)?;
    need(ack == [2], "leaf-after-grantor-death")?;
    need(
        report.read_timeout(&mut ack, TICKS) == Ok(0),
        "leaf-process-report-eof",
    )?;
    close(report.raw()).map_err(|_| "grantor-report-close")?;
    let end = resource_census().map_err(|_| "grantor-census")?;
    if end.cells != base.cells
        || end.pipes != base.pipes
        || end.handles != base.handles
        || end.frames != base.frames
        || end.processes != base.processes + 1
    {
        census_diagnostic(console, "grantor-cleanup", "before", base);
        census_diagnostic(console, "grantor-cleanup", "after", end);
    }
    // Init adopts the leaf. Its terminal slot is not this probe's child;
    // root cannot reap it. Do not subtract it from the final boot oracle.
    need(
        end.cells == base.cells && end.pipes == base.pipes && end.handles == base.handles,
        "grantor-object-cleanup",
    )?;
    // terminate releases address-space/stack frames before draining report
    // writers, so EOF also admits exact frame equality despite the retained
    // terminal process slot. Nothing is normalized out of this comparison.
    need(end.frames == base.frames, "grantor-frame-cleanup")?;
    need(
        end.processes == base.processes + 1,
        "adopted-leaf-terminal-slot",
    )?;
    absd_user::cprintln!(console, "CAP LEAF pid={leaf_pid}").map_err(|_| "output")?;
    absd_user::cprintln!(
        console,
        "CAP grantor-death gate-eof=true read=true object-census=equal terminal-slot=adopted"
    )
    .map_err(|_| "output")?;
    absd_user::cprintln!(console, "CAP OK").map_err(|_| "output")?;
    Ok(())
}
