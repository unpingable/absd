//! The kernel-started process. It drives the spawn/wait lifecycle:
//! 1. run the demonstration programs and check each outcome;
//! 2. fill the process table, prove spawn fails closed, then reap everything;
//! 3. cycle hundreds of short-lived children so the kernel can prove that
//!    frame usage returns to baseline.
#![no_std]
#![no_main]

use core::fmt::Write;

use absd_abi::layout::{USER_ADDRESS_LIMIT, USER_HEAP_BASE, USER_STACK_BASE, USER_STACK_TOP};
use absd_abi::syscall::{
    VECTOR_DIVIDE_ERROR, VECTOR_GENERAL_PROTECTION, VECTOR_INVALID_OPCODE, VECTOR_PAGE_FAULT,
    VECTOR_SIMD_ERROR,
};
use absd_user::program::{ServedEndFailure, ServedEscalation};
use absd_user::{
    Cell, Child, Console, Error, INFO_STATE_LIVE, INFO_STATE_TERMINAL, INFO_STATE_WAITING,
    LineBuffer, MAX_SPAWN_HANDLES, Outcome, Pipe, RIGHT_KILL, RIGHT_READ, RIGHT_WAIT, RIGHT_WRITE,
    SpawnHandleCopy, Start, abi_version, close, duplicate, getpid, info, kill, pipe_info,
    pipe_info_raw, program, resource_census, sleep, spawn, spawn_captured, spawn_many_copy,
    spawn_many_copy_raw, spawn_with, syscall3, time, wait, wait_any, wait_any_timeout,
    wait_timeout, wall_clock, yield_now,
};
use absd_user::{
    MACHINE_RIGHT_RECOVER, MACHINE_RIGHT_RESTART, MACHINE_RIGHT_STOP, STOP_CODE_MAX, STOP_CODE_MIN,
    machine_recover, machine_restart, machine_stop,
};
use absd_user::{frame_stats, frame_stats_raw, map, unmap};

/// Maximum child capacity with no kernel-reserved qualification processes.
const SPAWN_CAPACITY: usize = 15;
const PROCESS_TABLE_CAPACITY: usize = SPAWN_CAPACITY + 1;
const PRIVATE_TEST_SYSCALL: u64 = 0x7fff;
const TOPOLOGY_RESERVATION_OP: u64 = 12;
const STRESS_CYCLES: usize = 200;
const HANDLE_LIFETIME_CYCLES: usize = 8;
const OBJECT_CAPACITY_CYCLES: usize = 3;
/// Supervision must retain a live deadline so a stuck worker cannot leave the
/// machine parked forever in the kernel idle loop.
const SUPERVISOR_WAIT_TICKS: u64 = 500;
/// Lines the pipe child sends; 16 bytes each, more than the pipe holds.
const PIPER_LINES: u64 = 150;
const EXTERNAL_WAIT_TICKS: u64 = 120_000;
/// A worker holding the NIC in a qualification boot is a server whose run
/// is paced by its network peers, not by its input: it gets an hour, or
/// what the build's `ABSD_NET_WAIT_TICKS` says (a harness shortens it to
/// watch the deadline act). A served boot's worker has no deadline.
const NET_WAIT_TICKS_DEFAULT: u64 = 3_600_000;
const NET_WAIT_TICKS_BUILD: &str = env!("ABSD_NET_WAIT_TICKS");
/// How often init reaps ended orphans a server worker's descendants left
/// while the worker runs (see `reap_adopted_orphans`).
const ORPHAN_REAP_TICKS: u64 = 100;
const EXTERNAL_LIVE_IO_TICKS: u64 = 5_000;
const EXTERNAL_LIVE_MAX_BYTES: usize = 128 * 1024;
const EXTERNAL_LIVE_CREDIT: usize = 64;
const EXTERNAL_LIVE_MAGIC: &[u8; 8] = b"ABSDST01";
const EXTERNAL_INPUT: &[u8] = include_bytes!(env!("ABSD_EXTERNAL_INPUT_EMBED"));
const EXTERNAL_READER_INPUT: &[u8] = include_bytes!(env!("ABSD_EXTERNAL_READER_INPUT_EMBED"));
/// Whether this image carries an external reader for durable boots.
const EXTERNAL_READER_PRESENT: bool = !env!("ABSD_EXTERNAL_READER_PRESENT").is_empty();
/// Whether this image carries a file server for `fsd` durable boots.
const FILE_SERVER_PRESENT: bool = !env!("ABSD_FILE_SERVER_PRESENT").is_empty();
/// The control channel and the client slots of an `fsd` boot.
const FSD_CHANNELS: usize = 1 + program::FILE_SERVER_SLOTS;
/// How long init waits for the file server to finish after the worker
/// ended (it sees end of file on its control channel, commits, and exits).
const FSD_STOP_TICKS: u64 = 30_000;
/// After a served boot's worker and file server have ended: how long init
/// waits for the orphans the sessions left to end. Init cannot end them
/// (it holds no handle to an adopted process); if any is still alive then,
/// the orderly end escalates (`end_served`): a requested halt stops the
/// machine with `program::SERVED_UNREAPED_STOP_CODE`, a requested restart
/// takes the recovery reset. Storage is committed by then: the file server
/// has already stopped.
const SERVED_DRAIN_TICKS: u64 = 20_000;
/// A dead served worker may have left a descendant holding its captured
/// output pipe. Do not wait forever for that process to close the stream.
const SERVED_POST_WORKER_OUTPUT_TICKS: u64 = 10_000;
const SERVED_RECOVERY_STOP_TICKS: u64 = 1_000;
const SERVED_RECOVERY_DRAIN_TICKS: u64 = 2_000;
/// How long init waits for the file server's finalize run, which leaves
/// init's verdict for the next generation's recovery ledger after an
/// orderly end completed (one mount, one fact, one commit).
const SERVED_FINALIZE_TICKS: u64 = 5_000;

#[path = "../init_broker.rs"]
mod broker;

absd_user::entry!(main);

fn main(start: Start) -> i32 {
    let console = start.console;
    let _ = console.write_str("USER INIT STARTED\n");
    // The kernel's machine handle: init keeps it only in the modes whose
    // policy uses it (a durable boot grants the worker a stop-only copy; a
    // served boot restarts the machine on request). Elsewhere it is closed
    // at once: ending init ends those boots.
    let mode = program::init_mode(start.arg);
    let keeps_machine = start.arg == program::INIT_MODE_SUITE
        || start.arg == program::INIT_MODE_MACHINE_RECOVER_TEST
        || mode == program::INIT_MODE_DURABLE
        || mode == program::INIT_MODE_SERVED_FSD
        || mode == program::INIT_MODE_SERVED_FSD_EXIT_TEST;
    if keeps_machine {
        unsafe { MACHINE = start.machine };
    } else if start.machine != 0 && close(start.machine).is_err() {
        let _ = console.write_str("init: FAILED at machine handle close\n");
        return 99;
    }
    let result = match start.arg {
        program::INIT_MODE_SUITE => topology_reservation().and_then(|reserve| {
            let _ = console.write_str("init: spawning demonstration programs\n");
            run(console, reserve).and_then(|()| verify_machine_right(console))
        }),
        program::INIT_MODE_MACHINE_RECOVER_TEST => run_machine_recover_test(console),
        program::INIT_MODE_SHELL => bootstrap_child(console, program::SHELL),
        program::INIT_MODE_FUZZ => bootstrap_child(console, program::FUZZ),
        program::INIT_MODE_HOSTILE => run_hostile(console),
        program::INIT_MODE_FPU_TEST => run_fpu_test(console),
        program::INIT_MODE_RT_TEST => run_rt_test(console),
        program::INIT_MODE_RT_CLASS => run_rt_class(console),
        program::INIT_MODE_SMP_LIFECYCLE => run_smp_lifecycle(console),
        program::INIT_MODE_SMP_CREATED_STOP => {
            let _ = spawn(program::SLEEPER);
            Err("Created stop returned to spawner")
        }
        program::INIT_MODE_EXTERNAL => {
            topology_reservation().and_then(|_| run_external(console, false))
        }
        program::INIT_MODE_EXTERNAL_LIVE => run_external(console, true),
        arg if program::init_mode(arg) == program::INIT_MODE_BLOCK_PROBE => run_durable(
            console,
            start.handle,
            program::BLOCK_PROBE,
            program::init_step(arg),
        ),
        arg if program::init_mode(arg) == program::INIT_MODE_DURABLE => {
            // A `net` durable boot: the worker, and only the worker, also
            // gets the NIC (docs/NETWORK.md).
            unsafe { WORKER_NIC = start.nic };
            run_durable(
                console,
                start.handle,
                program::EXTERNAL_WORKLOAD,
                program::init_step(arg),
            )
        }
        arg if program::init_mode(arg) == program::INIT_MODE_DURABLE_FSD => {
            unsafe { WORKER_NIC = start.nic };
            run_durable_fsd(console, start.handle, program::init_step(arg), false)
        }
        arg if matches!(
            program::init_mode(arg),
            program::INIT_MODE_SERVED_FSD | program::INIT_MODE_SERVED_FSD_EXIT_TEST
        ) =>
        {
            unsafe {
                WORKER_NIC = start.nic;
                SERVED = true;
            }
            run_durable_fsd(
                console,
                start.handle,
                program::init_step(arg),
                program::init_mode(arg) == program::INIT_MODE_SERVED_FSD_EXIT_TEST,
            )
        }
        arg if program::init_mode(arg) == program::INIT_MODE_NET_PROBE => {
            run_net_probe(console, start.nic, program::init_step(arg))
        }
        _ => Err("unknown startup mode"),
    };
    match result {
        Ok(()) => {
            let _ = console.write_str("USERSPACE BOOTSTRAP OK\n");
            0
        }
        Err(step) => {
            // Only a fault during service is recovered here. Once the
            // worker's request was reaped, a failure finishes the orderly
            // end (`end_served` escalates it); once `end_served` ran, it
            // has decided.
            if served() {
                let request = unsafe { SERVED_REQUEST };
                match program::served_failure_route(
                    unsafe { SERVED_END_DECIDED },
                    request.is_some(),
                ) {
                    program::ServedFailureRoute::FaultRecovery => {
                        return recover_served(console, step);
                    }
                    program::ServedFailureRoute::OrderlyEnd => {
                        let mut line = LineBuffer::new();
                        let _ = writeln!(line, "SERVED SHUTDOWN STREAM FAILED step={step}");
                        let _ = external_line(console, &line);
                        if let Some(worker) = request {
                            let server_pid = unsafe { FSD_SERVER_PID };
                            let _ = end_served(console, worker, server_pid, true);
                        }
                    }
                    program::ServedFailureRoute::Decided => {}
                }
            }
            let _ = console.write_str("init: FAILED at ");
            let _ = console.write_str(step);
            let _ = console.write_str("\n");
            99
        }
    }
}

/// Read the number of kernel-owned qualification slots reserved beside init.
/// Older/non-qualification kernels return NOT_IMPLEMENTED and retain the
/// ordinary zero-reservation capacity.
fn topology_reservation() -> Result<usize, &'static str> {
    if getpid() != 1 {
        return Err("init identity before topology query");
    }
    let raw = unsafe { syscall3(PRIVATE_TEST_SYSCALL, TOPOLOGY_RESERVATION_OP, 0, 0) };
    let reserve = match raw {
        0 => 0,
        1 => 1,
        2 => 2,
        6 | 10 => {
            let cpus = unsafe { syscall3(PRIVATE_TEST_SYSCALL, TOPOLOGY_RESERVATION_OP, 1, 0) };
            if !matches!(cpus, 4 | 6) || raw != 2 * (cpus - 1) {
                return Err("multicore topology reservation query");
            }
            raw as usize
        }
        code if Error::from_code(code) == Error::NotImplemented => 0,
        _ => return Err("topology reservation query"),
    };
    require_process_count(1 + reserve, "initial process census")?;
    Ok(reserve)
}

fn require_process_count(expected: usize, step: &'static str) -> Result<(), &'static str> {
    let census = resource_census().map_err(|_| step)?;
    if census.processes != expected as u64 {
        return Err(step);
    }
    Ok(())
}

/// Closed N-way pressure needs a reservation before constructing a service.
/// Ordinary/legacy boots refuse this private CPU query and keep their policy.
fn reserve_multicore_service() -> Result<(), &'static str> {
    let cpus = unsafe { syscall3(PRIVATE_TEST_SYSCALL, TOPOLOGY_RESERVATION_OP, 1, 0) };
    match cpus {
        2 | 4 | 6 => topology_reservation().map(|_| ()),
        code if Error::from_code(code) == Error::NotImplemented => Ok(()),
        _ => Err("multicore service reservation query"),
    }
}

fn expect_client_service_process_baseline(reserve: usize) -> Result<(), &'static str> {
    require_process_count(2 + reserve, "client service drained census")
}

fn external_line(console: Console, line: &LineBuffer) -> Result<(), &'static str> {
    match console.write_once(line.as_bytes()) {
        Ok(written) if written == line.as_bytes().len() => Ok(()),
        _ => Err("external serial frame"),
    }
}

fn external_chunk(console: Console, offset: usize, bytes: &[u8]) -> Result<(), &'static str> {
    let mut line = LineBuffer::new();
    let _ = write!(line, "EXTERNAL OUTPUT CHUNK offset={offset:016x} data=");
    for byte in bytes {
        let _ = write!(line, "{byte:02x}");
    }
    let _ = writeln!(line);
    external_line(console, &line)
}

fn external_abort(child: Child, input_writer: Pipe, writer_open: bool, output_reader: Pipe) {
    if writer_open {
        let _ = close(input_writer.raw());
    }
    let _ = kill(child);
    if let Ok(outcome) = wait_timeout(Some(child), 500)
        && served()
    {
        unsafe { SERVED_WORKER_HANDLE = 0 };
        note_served_worker(outcome);
    }
    let _ = close(output_reader.raw());
}

fn live_input_refused(console: Console, reason: &str) {
    let mut line = LineBuffer::new();
    let _ = writeln!(line, "EXTERNAL INPUT REFUSED reason={reason}");
    let _ = external_line(console, &line);
}

fn console_read_exact(
    console: Console,
    mut bytes: &mut [u8],
    deadline: u64,
) -> Result<(), &'static str> {
    while !bytes.is_empty() {
        if time() >= deadline {
            return Err("external live input timeout");
        }
        match console.read_timeout(bytes, 2) {
            Ok(0) => return Err("external live input eof"),
            Ok(count) => bytes = &mut bytes[count..],
            Err(Error::Timeout) => {}
            Err(_) => return Err("external live input read"),
        }
    }
    Ok(())
}

fn write_pipe_exact(writer: Pipe, mut bytes: &[u8], deadline: u64) -> Result<(), &'static str> {
    while !bytes.is_empty() {
        if time() >= deadline {
            return Err("external live pipe timeout");
        }
        match writer.write_timeout(bytes, 2) {
            Ok(0) => return Err("external live zero pipe write"),
            Ok(count) => bytes = &bytes[count..],
            Err(Error::Timeout) => {}
            Err(_) => return Err("external live pipe write"),
        }
    }
    Ok(())
}

fn receive_live_input(
    console: Console,
    writer: Pipe,
    deadline: u64,
) -> Result<usize, &'static str> {
    external_line(console, &{
        let mut line = LineBuffer::new();
        let _ = writeln!(
            line,
            "EXTERNAL INPUT READY protocol=absd-stream-v1 max={EXTERNAL_LIVE_MAX_BYTES} credit={EXTERNAL_LIVE_CREDIT}"
        );
        line
    })?;
    let mut magic = [0u8; 8];
    let input_deadline = time().saturating_add(EXTERNAL_LIVE_IO_TICKS).min(deadline);
    if let Err(error) = console_read_exact(console, &mut magic, input_deadline) {
        live_input_refused(console, "header-timeout");
        return Err(error);
    }
    if &magic != EXTERNAL_LIVE_MAGIC {
        live_input_refused(console, "bad-header");
        return Err("external live input header");
    }
    external_line(console, &{
        let mut line = LineBuffer::new();
        let _ = writeln!(line, "EXTERNAL INPUT ACCEPTED protocol=absd-stream-v1");
        line
    })?;

    let mut total = 0usize;
    loop {
        let remaining = EXTERNAL_LIVE_MAX_BYTES - total;
        let credit = remaining.min(EXTERNAL_LIVE_CREDIT);
        let mut line = LineBuffer::new();
        let _ = writeln!(line, "EXTERNAL INPUT CREDIT offset={total} max={credit}");
        external_line(console, &line)?;

        let mut length_bytes = [0u8; 2];
        let input_deadline = time().saturating_add(EXTERNAL_LIVE_IO_TICKS).min(deadline);
        if let Err(error) = console_read_exact(console, &mut length_bytes, input_deadline) {
            live_input_refused(console, "truncated-chunk-header");
            return Err(error);
        }
        let length = usize::from(u16::from_be_bytes(length_bytes));
        if length == 0 {
            let mut line = LineBuffer::new();
            let _ = writeln!(line, "EXTERNAL INPUT EOF bytes={total}");
            external_line(console, &line)?;
            close(writer.raw()).map_err(|_| "external live input close")?;
            return Ok(total);
        }
        if length > credit {
            live_input_refused(console, "chunk-exceeds-credit");
            return Err("external live input credit");
        }
        let mut payload = [0u8; EXTERNAL_LIVE_CREDIT];
        let input_deadline = time().saturating_add(EXTERNAL_LIVE_IO_TICKS).min(deadline);
        if let Err(error) = console_read_exact(console, &mut payload[..length], input_deadline) {
            live_input_refused(console, "truncated-chunk-payload");
            return Err(error);
        }
        write_pipe_exact(writer, &payload[..length], deadline)?;
        total += length;
    }
}

/// A durable boot: the kernel handed init the block device in RSI. The
/// selected multi-start program receives the input pipe, the block device,
/// a read-only cell carrying this boot's step number, and its captured
/// console, in that order.
fn run_durable(console: Console, block: u64, selected: u64, step: u64) -> Result<(), &'static str> {
    if block == 0 {
        return Err("no block device");
    }
    reserve_multicore_service()?;
    if broker::enabled() {
        broker::check_policy()?;
    }
    // Worker generations: a worker that ends with the abort status is
    // replaced, up to the bound, with one added to the step word's
    // replacement digit so the replacement knows it is resuming and takes
    // its progress from the device's evidence. Any other outcome
    // ends the boot. Every generation gets fresh pipes and a fresh cell;
    // nothing volatile passes from one worker to the next.
    let mut step = step;
    let mut generation = 1u64;
    loop {
        let step_cell = Cell::create(step).map_err(|_| "durable step cell")?;
        let extra = [
            SpawnHandleCopy::new(block, RIGHT_READ | RIGHT_WRITE),
            SpawnHandleCopy::new(step_cell.raw(), RIGHT_READ),
        ];
        let outcome = run_external_with(
            console,
            false,
            selected,
            &extra,
            EXTERNAL_INPUT,
            Party::Worker(generation),
        );
        if broker::enabled() {
            // However the worker's run ended, nothing it asked for outlives
            // it; the success path has already done this.
            broker::close_worker(console);
            let stats = broker::stats();
            let mut line = LineBuffer::new();
            let _ = writeln!(
                line,
                "BROKER SUMMARY generation={generation} requests={} dropped={} started={} refused={} exited={} reclaimed={} idle={}",
                stats.requests,
                stats.dropped,
                stats.started,
                stats.refused,
                stats.exited,
                stats.reclaimed,
                broker::idle()
            );
            external_line(console, &line)?;
            if !broker::idle() {
                return Err("broker left a child or channel behind");
            }
        }
        close(step_cell.raw()).map_err(|_| "durable step cell close")?;
        let result = match outcome? {
            Outcome::Exited(0) => Ok(()),
            Outcome::Exited(status) if status == program::DURABLE_WORKER_ABORT_STATUS => {
                if generation >= program::DURABLE_MAX_GENERATIONS {
                    return Err("durable worker generations exhausted");
                }
                no_live_descendant()?;
                step = program::durable_replacement_step(step);
                generation += 1;
                continue;
            }
            _ => Err("durable worker outcome"),
        };
        // The reader reads what the worker left durable, whatever the worker's
        // outcome: a refused or failed write still leaves committed state.
        if EXTERNAL_READER_PRESENT {
            no_live_descendant()?;
            let reader = run_reader(console, block, step);
            return result.and(reader);
        }
        return result;
    }
}

/// An `fsd` durable boot: the file server is the only process with the
/// read-write block handle; the worker gets a control channel and client
/// channels to it and no block handle at all. Init mints every channel
/// before either starts (a handle exists only at spawn), keeps no end of
/// any, and gives the server its ends first. One worker generation: the
/// client ends are gone once the worker has them, so no replacement could
/// get them. The boot fails if the server ends while the worker runs.
fn run_durable_fsd(
    console: Console,
    block: u64,
    step: u64,
    qualification_exit: bool,
) -> Result<(), &'static str> {
    if block == 0 {
        return Err("no block device");
    }
    reserve_multicore_service()?;
    if !FILE_SERVER_PRESENT {
        return Err("fsd boot without a file server image");
    }
    if broker::enabled() || EXTERNAL_READER_PRESENT {
        return Err("fsd boot takes no broker policy or reader");
    }
    // server[i] = (request reader, reply writer); client[i] the opposite.
    let mut server = [(0u64, 0u64); FSD_CHANNELS];
    let mut client = [(0u64, 0u64); FSD_CHANNELS];
    for index in 0..FSD_CHANNELS {
        let (request_reader, request_writer) = split_pipe()?;
        let (reply_reader, reply_writer) = split_pipe()?;
        server[index] = (request_reader, reply_writer);
        client[index] = (request_writer, reply_reader);
    }
    let (server_child, server_pid) =
        spawn_file_server(console, block, &server, qualification_exit)?;
    for (request, reply) in server {
        close(request).map_err(|_| "fsd server end close")?;
        close(reply).map_err(|_| "fsd server end close")?;
    }
    unsafe {
        FSD_CLIENT = client;
        FSD_SERVER_PID = server_pid;
        if served() {
            FSD_SERVER_HANDLE = server_child.raw();
            SERVED_BLOCK = block;
        }
    }
    let mut line = LineBuffer::new();
    let _ = writeln!(
        line,
        "FILE SERVER START pid={server_pid} channels={FSD_CHANNELS}"
    );
    external_line(console, &line)?;
    let step_cell = Cell::create(step).map_err(|_| "durable step cell")?;
    let extra = [SpawnHandleCopy::new(step_cell.raw(), RIGHT_READ)];
    let outcome = run_external_with(
        console,
        false,
        program::EXTERNAL_WORKLOAD,
        &extra,
        EXTERNAL_INPUT,
        Party::Worker(1),
    );
    close(step_cell.raw()).map_err(|_| "durable step cell close")?;
    if served() {
        // An exit 0 or 98 is the operator's request: `end_served` decides
        // its outcome. Anything else is a fault during service; the step
        // names which component (the worker's own outcome, or the file
        // server ending while the worker ran, or a stream failure).
        return match outcome {
            Ok(
                worker @ (Outcome::Exited(0)
                | Outcome::Exited(program::SERVED_WORKER_RESTART_STATUS)),
            ) => end_served(console, worker, server_pid, false),
            Ok(_) => Err("served worker fault"),
            Err(step) => Err(step),
        };
    }
    // The worker's client ends (and init's copies, closed at its spawn)
    // are gone: the server reads end of file on its control channel and
    // stops. A server that already ended was reaped above.
    let server_status = match unsafe { FSD_SERVER_OUTCOME } {
        Some(status) => status,
        None => {
            let deadline = time().saturating_add(FSD_STOP_TICKS);
            loop {
                match wait_any_timeout(1) {
                    Ok(result) if result.pid == server_pid => {
                        unsafe { FSD_SERVER_HANDLE = 0 };
                        break outcome_status(result.outcome);
                    }
                    Ok(result) => {
                        let mut line = LineBuffer::new();
                        let _ = writeln!(line, "INIT ORPHAN REAPED pid={}", result.pid);
                        external_line(console, &line)?;
                    }
                    Err(Error::Timeout) if time() < deadline => {}
                    Err(_) => return Err("file server did not stop"),
                }
            }
        }
    };
    let mut line = LineBuffer::new();
    let _ = writeln!(
        line,
        "FILE SERVER OUTCOME pid={server_pid} status={server_status}"
    );
    external_line(console, &line)?;
    let outcome = outcome?;
    let result = match outcome {
        Outcome::Exited(0) => Ok(()),
        _ => Err("durable worker outcome"),
    };
    no_live_descendant()?;
    if server_status != 0 {
        return Err("file server outcome");
    }
    result
}

/// The end of a served boot. The worker (sshd) has ended its sessions and
/// exited, asking for a halt (0) or a restart; the file server sees its
/// control channel close, commits, and stops. Init waits for the file
/// server, reaps what the sessions left, then either returns (the kernel's
/// end-of-boot accounting halts the machine) or arms the restart first,
/// with its own right. An orderly end that cannot finish as asked
/// escalates here and never reaches `recover_served`: a requested halt
/// stops the machine, a requested restart takes the recovery reset
/// (docs/PROCESS-STARTUP.md, "Served boot and orderly shutdown"). Console
/// write failures do not change the outcome.
fn end_served(
    console: Console,
    worker: Outcome,
    server_pid: u64,
    stream_failed: bool,
) -> Result<(), &'static str> {
    unsafe { SERVED_END_DECIDED = true };
    let restart = worker == Outcome::Exited(program::SERVED_WORKER_RESTART_STATUS);
    // A file server that did not end reports status -1.
    let (server_status, server_failure) = match unsafe { FSD_SERVER_OUTCOME } {
        Some(status) => (status, None),
        None => {
            let deadline = time().saturating_add(FSD_STOP_TICKS);
            loop {
                match wait_any_timeout(1) {
                    Ok(result) if result.pid == server_pid => {
                        unsafe { FSD_SERVER_HANDLE = 0 };
                        break (outcome_status(result.outcome), None);
                    }
                    Ok(result) => {
                        let mut line = LineBuffer::new();
                        let _ = writeln!(line, "INIT ORPHAN REAPED pid={}", result.pid);
                        let _ = external_line(console, &line);
                    }
                    Err(Error::Timeout) if time() < deadline => {}
                    Err(Error::Timeout) => break (-1, Some(ServedEndFailure::FileServerTimeout)),
                    Err(_) => break (-1, Some(ServedEndFailure::FileServerWait)),
                }
            }
        }
    };
    if server_failure.is_none() {
        let mut line = LineBuffer::new();
        let _ = writeln!(
            line,
            "FILE SERVER OUTCOME pid={server_pid} status={server_status}"
        );
        let _ = external_line(console, &line);
    }
    let server_failure = match server_failure {
        None if server_status != 0 => Some(ServedEndFailure::FileServerStatus),
        failure => failure,
    };
    if let Some(failure) = server_failure {
        served_shutdown_line(console, worker, server_status, 0, false);
        return escalate_served(console, restart, failure);
    }
    let deadline = time().saturating_add(SERVED_DRAIN_TICKS);
    let mut reaped = 0u64;
    let drained = loop {
        match wait_any_timeout(1) {
            Err(Error::NoChild) => break Ok(()),
            Ok(result) => {
                reaped += 1;
                let mut line = LineBuffer::new();
                let _ = writeln!(line, "INIT ORPHAN REAPED pid={}", result.pid);
                let _ = external_line(console, &line);
            }
            Err(Error::Timeout) if time() < deadline => {}
            Err(Error::Timeout) => break Err(ServedEndFailure::Unreaped),
            Err(_) => break Err(ServedEndFailure::DrainWait),
        }
    };
    served_shutdown_line(console, worker, server_status, reaped, drained.is_ok());
    if let Err(failure) = drained {
        // A process the sessions left may still be running and init cannot
        // end it. The file server already stopped after committing.
        if failure == ServedEndFailure::Unreaped {
            let _ = external_line(
                console,
                &line_of("SERVED SHUTDOWN UNREAPED adopted_child_residue=true"),
            );
        }
        return escalate_served(console, restart, failure);
    }
    if stream_failed {
        return escalate_served(console, restart, ServedEndFailure::WorkerStream);
    }
    // The end completed as asked: file server status 0, every orphan
    // reaped within the bound, the worker's stream clean. Only now is
    // init's verdict recorded, by the file server run once more in its
    // finalize mode with the block handle init kept: the next
    // generation's recovery ledger clears its streak on that fact, not on
    // sshd's request or the server's own stop. A finalize that fails or
    // overruns leaves the streak uncleared and changes nothing else.
    finalize_served(console);
    if restart {
        machine_restart(unsafe { MACHINE }).map_err(|_| "served restart refused")?;
    }
    Ok(())
}

/// Runs the file server in finalize mode and reports its outcome; the
/// requested end proceeds whatever that outcome is.
fn finalize_served(console: Console) {
    use absd_user::broker::{ROLE_BLOCK, ROLE_STDIN, ROLE_STEP, startup_record};
    let block = unsafe { SERVED_BLOCK };
    let mut line = LineBuffer::new();
    // The runtime takes a startup record only on a vector of at least
    // five handles with every middle one named: the durable shape
    // (stdin, block, step, console) behind a record carrying `--finalize`.
    let outcome: Result<Outcome, &'static str> = (|| {
        if block == 0 {
            return Err("no block handle");
        }
        let (startup_reader, startup_writer) = split_pipe()?;
        let startup_writer = Pipe::from_raw(startup_writer);
        let (stdin_reader, stdin_writer) = split_pipe()?;
        close(stdin_writer).map_err(|_| "finalize stdin writer close")?;
        let step = Cell::create(0).map_err(|_| "finalize step cell")?;
        let copies = [
            SpawnHandleCopy::new(startup_reader, RIGHT_READ),
            SpawnHandleCopy::new(stdin_reader, RIGHT_READ),
            SpawnHandleCopy::new(block, RIGHT_READ | RIGHT_WRITE),
            SpawnHandleCopy::new(step.raw(), RIGHT_READ),
            SpawnHandleCopy::console(console.raw(), RIGHT_WRITE),
        ];
        let roles = [(ROLE_STDIN, 1u8), (ROLE_BLOCK, 2u8), (ROLE_STEP, 3u8)];
        let spawned = spawn_many_copy(
            program::FILE_SERVER | absd_abi::syscall::SPAWN_NO_SPAWN,
            &copies,
        );
        let _ = close(startup_reader);
        let _ = close(stdin_reader);
        let _ = close(step.raw());
        let child = spawned.map_err(|_| "finalize spawn")?;
        const FLAG: &[u8] = b"--finalize";
        let mut encoded = [0u8; 4 + FLAG.len()];
        encoded[..2].copy_from_slice(&1u16.to_le_bytes());
        encoded[2..4].copy_from_slice(&(FLAG.len() as u16).to_le_bytes());
        encoded[4..].copy_from_slice(FLAG);
        let mut record = [0u8; 128];
        let length =
            startup_record(&mut record, &roles, &encoded).ok_or("finalize startup record")?;
        startup_writer
            .write_all(&record[..length])
            .map_err(|_| "finalize startup write")?;
        close(startup_writer.raw()).map_err(|_| "finalize startup close")?;
        match wait_timeout(Some(child), SERVED_FINALIZE_TICKS) {
            Ok(outcome) => Ok(outcome),
            Err(Error::Timeout) => {
                let _ = kill(child);
                let _ = wait_timeout(Some(child), SERVED_RECOVERY_STOP_TICKS);
                Err("finalize timeout")
            }
            Err(_) => Err("finalize wait"),
        }
    })();
    match outcome {
        Ok(outcome) => {
            let _ = writeln!(
                line,
                "SERVED SHUTDOWN FINALIZED status={}",
                outcome_status(outcome)
            );
        }
        Err(step) => {
            let _ = writeln!(line, "SERVED SHUTDOWN FINALIZE FAILED step={step}");
        }
    }
    let _ = external_line(console, &line);
}

/// The one `SERVED SHUTDOWN action=` line every orderly end prints, before
/// any escalation.
fn served_shutdown_line(
    console: Console,
    worker: Outcome,
    server_status: i64,
    reaped: u64,
    drained: bool,
) {
    let action = if worker == Outcome::Exited(program::SERVED_WORKER_RESTART_STATUS) {
        "restart"
    } else {
        "halt"
    };
    let mut line = LineBuffer::new();
    let _ = writeln!(
        line,
        "SERVED SHUTDOWN action={action} worker_status={} file_server_status={server_status} orphans_reaped={reaped} drained={drained}",
        outcome_status(worker)
    );
    let _ = external_line(console, &line);
}

/// A failed orderly end: one marker, then the outcome the operator's
/// request decides. A requested halt stops the machine (it never comes back
/// up); a requested restart takes the whole-machine recovery reset, whose
/// census the kernel prints, once the generation was ready, and stops
/// before that (reason suffixed `_before_ready`). Returns only if the kernel refused; main then
/// fails the boot without a reset.
fn escalate_served(
    console: Console,
    restart: bool,
    failure: ServedEndFailure,
) -> Result<(), &'static str> {
    let ready = unsafe { SERVED_READY };
    let escalation = failure.escalation(restart, ready);
    let mut line = LineBuffer::new();
    let _ = writeln!(
        line,
        "SERVED SHUTDOWN ESCALATED requested={} reason={}{} outcome={} code={}",
        if restart { "restart" } else { "halt" },
        failure.reason(),
        if restart && !ready {
            "_before_ready"
        } else {
            ""
        },
        escalation.name(),
        failure.code()
    );
    let _ = external_line(console, &line);
    let machine = unsafe { MACHINE };
    let refusal = match escalation {
        ServedEscalation::Stop(code) => machine_stop(machine, code),
        ServedEscalation::RecoveryReset => machine_recover(machine),
    };
    let mut line = LineBuffer::new();
    let _ = writeln!(line, "SERVED SHUTDOWN ESCALATION REFUSED error={refusal:?}");
    let _ = external_line(console, &line);
    Err("served escalation refused")
}

/// A failed served generation is recovered by a whole-machine reset, at
/// most `SERVED_RECOVERY_BUDGET` times in a row: the recovery streak sshd
/// advertised before readiness (charged durably by the file server, see
/// docs/service-lifecycle-20261008/RECOVERY-BUDGET.md) decides whether
/// this failure resets the machine or stops it with a named code. This
/// first attempts bounded process stop/wait, but adopted live descendants
/// have no kill handle in init and are reported as residue. The reset is not
/// a process reclamation fence or a filesystem sync. A second boot mounts
/// committed metadata or refuses it under the filesystem's rules; data
/// without a completed sync may reflect a subset of prior writes.
fn recover_served(console: Console, reason: &'static str) -> i32 {
    if !unsafe { SERVED_READY } {
        let _ = console.write_str("SERVED RECOVERY REFUSED generation_not_ready\n");
        let _ = console.write_str("init: FAILED at ");
        let _ = console.write_str(reason);
        let _ = console.write_str("\n");
        return 99;
    }
    let mut line = LineBuffer::new();
    match unsafe { FSD_SERVER_OUTCOME } {
        Some(status) => {
            let _ = writeln!(
                line,
                "SERVED RECOVERY BEGIN reason={reason} file_server_status={status}"
            );
        }
        None => {
            let _ = writeln!(
                line,
                "SERVED RECOVERY BEGIN reason={reason} file_server_status=running"
            );
        }
    }
    let _ = external_line(console, &line);
    let worker = unsafe { SERVED_WORKER_HANDLE };
    let server = unsafe { FSD_SERVER_HANDLE };
    stop_served_process(console, "sshd", worker);
    stop_served_process(console, "fsd", server);

    let deadline = time().saturating_add(SERVED_RECOVERY_DRAIN_TICKS);
    let mut reaped = 0u64;
    let drained = loop {
        match wait_any_timeout(1) {
            Ok(result) => {
                reaped += 1;
                let mut line = LineBuffer::new();
                let _ = writeln!(
                    line,
                    "SERVED RECOVERY REAP pid={} outcome={}",
                    result.pid,
                    outcome_status(result.outcome)
                );
                let _ = external_line(console, &line);
            }
            Err(Error::NoChild) => break true,
            Err(Error::Timeout) if time() < deadline => {}
            Err(_) => break false,
        }
    };
    // Init is the only writer of the probe; read it through a raw pointer
    // like `observe_served_ready` does.
    let streak = unsafe { (*core::ptr::addr_of!(SERVED_READY_PROBE)).streak() };
    let refusal = match (program::recovery_decision(streak), streak) {
        (program::RecoveryDecision::Reset, Some(streak)) => {
            let mut line = LineBuffer::new();
            let _ = writeln!(
                line,
                "SERVED RECOVERY RESET reaped={reaped} children_drained={drained} streak={streak} budget={} durability=completed_sync_only",
                program::SERVED_RECOVERY_BUDGET
            );
            let _ = external_line(console, &line);
            machine_recover(unsafe { MACHINE })
        }
        // A reset is decided only on an advertised streak; without one
        // the decision is a stop, so this arm never prints a made-up 0.
        (program::RecoveryDecision::Reset, None) => {
            let _ = external_line(
                console,
                &line_of("SERVED RECOVERY REFUSED reset_without_streak"),
            );
            Error::Invalid
        }
        (program::RecoveryDecision::Stop { code, reason: why }, _) => {
            // The budget is spent (or was never advertised): the machine
            // stops with a named code and does not come back by itself.
            let mut line = LineBuffer::new();
            let _ = write!(line, "SERVED RECOVERY ESCALATED reason={why} streak=");
            match streak {
                Some(streak) => {
                    let _ = write!(line, "{streak}");
                }
                None => {
                    let _ = write!(line, "unknown");
                }
            }
            let _ = writeln!(
                line,
                " budget={} reaped={reaped} children_drained={drained} outcome=stop code={code}",
                program::SERVED_RECOVERY_BUDGET
            );
            let _ = external_line(console, &line);
            machine_stop(unsafe { MACHINE }, code)
        }
    };
    let mut line = LineBuffer::new();
    let _ = writeln!(line, "SERVED RECOVERY REFUSED error={refusal:?}");
    let _ = external_line(console, &line);
    99
}

/// Best effort is measured here; a failed stop or wait never becomes a
/// fabricated drain claim. Kernel machine reset is the fallback boundary.
fn stop_served_process(console: Console, name: &str, handle: u64) {
    if handle == 0 {
        let mut line = LineBuffer::new();
        let _ = writeln!(
            line,
            "SERVED RECOVERY SERVICE name={name} state=already_reaped_or_absent"
        );
        let _ = external_line(console, &line);
        return;
    }
    let child = Child::from_raw(handle);
    let Ok(identity) = info(Some(child)) else {
        let mut line = LineBuffer::new();
        let _ = writeln!(
            line,
            "SERVED RECOVERY SERVICE name={name} state=stale_handle"
        );
        let _ = external_line(console, &line);
        return;
    };
    let stop = if identity.state == INFO_STATE_TERMINAL {
        Ok(())
    } else {
        kill(child)
    };
    let joined = wait_timeout(Some(child), SERVED_RECOVERY_STOP_TICKS);
    let mut line = LineBuffer::new();
    let _ = writeln!(
        line,
        "SERVED RECOVERY SERVICE name={name} pid={} stop={stop:?} wait={joined:?}",
        identity.pid
    );
    let _ = external_line(console, &line);
}

fn line_of(text: &str) -> LineBuffer {
    let mut line = LineBuffer::new();
    let _ = writeln!(line, "{text}");
    line
}

/// Init's machine handle (stop, restart, and recover rights) while its mode's policy
/// uses it; zero otherwise.
static mut MACHINE: u64 = 0;
/// A served boot (`fsd served`): no worker deadline, and the worker's exit
/// asks for a halt or a restart.
static mut SERVED: bool = false;
/// Set once `end_served` runs: from then on it has decided the outcome and
/// `recover_served` never runs.
static mut SERVED_END_DECIDED: bool = false;
/// The served worker's exit 0 (halt) or 98 (restart), recorded the moment
/// init reaps it, before anything else can fail.
static mut SERVED_REQUEST: Option<Outcome> = None;

/// Records the operator's request when the served worker is reaped.
fn note_served_worker(outcome: Outcome) {
    if served()
        && matches!(
            outcome,
            Outcome::Exited(0) | Outcome::Exited(program::SERVED_WORKER_RESTART_STATUS)
        )
    {
        unsafe { SERVED_REQUEST = Some(outcome) };
    }
}

fn served() -> bool {
    unsafe { SERVED }
}

/// The qualification deadline of a NIC worker, from the build or the
/// default hour.
fn net_wait_ticks() -> u64 {
    NET_WAIT_TICKS_BUILD
        .parse()
        .unwrap_or(NET_WAIT_TICKS_DEFAULT)
}

/// The machine handle is authority like any other handle: it narrows, it
/// names nothing in another process, and the kernel refuses every attempt
/// to end the machine without the right, including the retired
/// boot-mode-gated `stop` (syscall 28). The suite then closes it.
fn verify_machine_right(console: Console) -> Result<(), &'static str> {
    let machine = unsafe { MACHINE };
    if machine == 0 {
        return Err("no machine handle");
    }
    if duplicate(machine, RIGHT_READ) != Err(Error::Rights) {
        return Err("machine handle took a right outside its kind");
    }
    let stop_only = duplicate(machine, MACHINE_RIGHT_STOP).map_err(|_| "machine stop-only")?;
    let restart_only =
        duplicate(machine, MACHINE_RIGHT_RESTART).map_err(|_| "machine restart-only")?;
    let recover_only =
        duplicate(machine, MACHINE_RIGHT_RECOVER).map_err(|_| "machine recover-only")?;
    let retired = unsafe { absd_user::syscall3(28, STOP_CODE_MIN, 0, 0) };
    // Each right is its own: restart does not imply recover, and recover
    // implies neither stop nor restart. Every refusal is logged.
    if machine_stop(restart_only, STOP_CODE_MIN) != Error::Rights
        || machine_restart(stop_only) != Err(Error::Rights)
        || machine_recover(stop_only) != Error::Rights
        || machine_recover(restart_only) != Error::Rights
        || machine_stop(recover_only, STOP_CODE_MIN) != Error::Rights
        || machine_restart(recover_only) != Err(Error::Rights)
        || machine_recover(0) != Error::BadHandle
        || machine_stop(stop_only, STOP_CODE_MIN - 1) != Error::Invalid
        || machine_stop(stop_only, STOP_CODE_MAX + 1) != Error::Invalid
        || machine_stop(0, STOP_CODE_MIN) != Error::BadHandle
        || machine_stop(console.raw(), STOP_CODE_MIN) != Error::BadHandle
        || retired != absd_abi::syscall::ERROR_NOT_IMPLEMENTED
    {
        return Err("machine right refusal");
    }
    // A child holds no machine handle unless one is copied to it: init's
    // handle value names nothing there, and a restart-only copy can neither
    // recover nor stop.
    for (handed, refused) in [(0, 1), (restart_only, 2)] {
        let child = spawn_with(program::MACHINE_PROBE, handed, machine)
            .map_err(|_| "machine probe spawn")?;
        if wait(Some(child)) != Ok(Outcome::Exited(refused)) {
            return Err("machine probe outcome");
        }
    }
    for handle in [stop_only, restart_only, recover_only, machine] {
        close(handle).map_err(|_| "machine handle close")?;
    }
    unsafe { MACHINE = 0 };
    let _ = console.write_str("MACHINE RIGHT OK\n");
    Ok(())
}

/// The `machine-recover-test` boot: neither PID 1 nor the boot mode
/// authorizes `machine_recover`, the handle does. Init hands a recover-only
/// duplicate to a child and keeps nothing else; the child's request resets
/// the machine, so returning here at all is the failure.
fn run_machine_recover_test(console: Console) -> Result<(), &'static str> {
    let machine = unsafe { MACHINE };
    if machine == 0 {
        return Err("no machine handle");
    }
    let recover_only =
        duplicate(machine, MACHINE_RIGHT_RECOVER).map_err(|_| "machine recover-only")?;
    close(machine).map_err(|_| "machine handle close")?;
    unsafe { MACHINE = 0 };
    let _ = console.write_str("MACHINE RECOVER TEST handing recover-only handle\n");
    let child = spawn_with(program::MACHINE_PROBE, recover_only, machine)
        .map_err(|_| "machine probe spawn")?;
    let _ = wait(Some(child));
    Err("machine recover through a recover-only handle returned")
}

fn split_pipe() -> Result<(u64, u64), &'static str> {
    let both = Pipe::create().map_err(|_| "fsd channel pipe")?;
    let reader = duplicate(both.raw(), RIGHT_READ).map_err(|_| "fsd channel reader")?;
    let writer = duplicate(both.raw(), RIGHT_WRITE).map_err(|_| "fsd channel writer")?;
    close(both.raw()).map_err(|_| "fsd channel split")?;
    Ok((reader, writer))
}

fn outcome_status(outcome: Outcome) -> i64 {
    match outcome {
        Outcome::Exited(status) => status as i64,
        Outcome::Faulted { vector, .. } => -(vector as i64) - 1000,
        Outcome::Killed => -1,
    }
}

/// Starts the catalog's file server without the spawn right:
/// `[startup, block, (request, reply) per channel, console]`, the block
/// handle read-write, the console init's own (its lines go straight to the
/// serial log, outside the worker's captured stream).
fn spawn_file_server(
    console: Console,
    block: u64,
    server: &[(u64, u64); FSD_CHANNELS],
    qualification_exit: bool,
) -> Result<(Child, u64), &'static str> {
    use absd_user::broker::{ROLE_BLOCK, ROLE_FS_REPLY, ROLE_FS_REQUEST, startup_record};
    let (startup_reader, startup_writer) = split_pipe()?;
    let startup_writer = Pipe::from_raw(startup_writer);
    let mut copies = [SpawnHandleCopy::new(0, 0); 3 + 2 * FSD_CHANNELS];
    let mut roles = [(0u8, 0u8); 1 + 2 * FSD_CHANNELS];
    copies[0] = SpawnHandleCopy::new(startup_reader, RIGHT_READ);
    copies[1] = SpawnHandleCopy::new(block, RIGHT_READ | RIGHT_WRITE);
    roles[0] = (ROLE_BLOCK, 1);
    for (index, (request, reply)) in server.iter().enumerate() {
        let at = 2 + 2 * index;
        copies[at] = SpawnHandleCopy::new(*request, RIGHT_READ);
        copies[at + 1] = SpawnHandleCopy::new(*reply, RIGHT_WRITE);
        roles[1 + 2 * index] = (ROLE_FS_REQUEST, at as u8);
        roles[2 + 2 * index] = (ROLE_FS_REPLY, at as u8 + 1);
    }
    copies[2 + 2 * FSD_CHANNELS] = SpawnHandleCopy::console(console.raw(), RIGHT_WRITE);
    let spawned = spawn_many_copy(
        program::FILE_SERVER | absd_abi::syscall::SPAWN_NO_SPAWN,
        &copies,
    );
    close(startup_reader).map_err(|_| "fsd startup reader close")?;
    let child = spawned.map_err(|_| "file server spawn")?;
    let mut record = [0u8; 256];
    // The record, not the ELF's build-time argv, controls a kernel-started
    // file server. Only this named local VM mode passes a failure flag.
    const EXIT_FLAG: &[u8] = b"--qualification-exit-on-notice";
    let mut encoded = [0u8; 4 + EXIT_FLAG.len()];
    let args = if qualification_exit {
        encoded[..2].copy_from_slice(&1u16.to_le_bytes());
        encoded[2..4].copy_from_slice(&(EXIT_FLAG.len() as u16).to_le_bytes());
        encoded[4..].copy_from_slice(EXIT_FLAG);
        &encoded[..]
    } else {
        &[0, 0][..]
    };
    let length = startup_record(&mut record, &roles, args).ok_or("fsd startup record")?;
    startup_writer
        .write_all(&record[..length])
        .map_err(|_| "fsd startup write")?;
    close(startup_writer.raw()).map_err(|_| "fsd startup close")?;
    Ok((
        child,
        info(Some(child)).map_err(|_| "file server identity")?.pid,
    ))
}

/// The client ends of an `fsd` boot's channels until the worker has them;
/// zero otherwise.
static mut FSD_CLIENT: [(u64, u64); FSD_CHANNELS] = [(0, 0); FSD_CHANNELS];
/// The file server's PID in an `fsd` boot; zero otherwise.
static mut FSD_SERVER_PID: u64 = 0;
/// Init's original process handle is kept for a served failure boundary.
/// This does not grant init authority over adopted descendants.
static mut FSD_SERVER_HANDLE: u64 = 0;
/// The process handle originally returned for sshd. It is retained by init
/// for bounded stop attempts if the served generation fails.
static mut SERVED_WORKER_HANDLE: u64 = 0;
/// Only the captured SSH listener record proves this generation ready.
/// Pre-ready startup failure refuses automatic reset of a broken image.
static mut SERVED_READY: bool = false;
static mut SERVED_READY_PROBE: program::ServedReadyProbe = program::ServedReadyProbe::new();
/// The file server's status if it ended while the worker ran.
static mut FSD_SERVER_OUTCOME: Option<i64> = None;
/// The block handle init keeps through a served boot, regranted once to
/// the file server's finalize run at a completed orderly end.
static mut SERVED_BLOCK: u64 = 0;

fn fsd_boot() -> bool {
    unsafe { FSD_SERVER_PID != 0 }
}

/// The exclusive-writer rule holds only if nothing the worker started outlives
/// it: a descendant could still hold the read-write block handle. Orphans
/// come to init, so init reaps any that have ended and refuses to go on while
/// one is alive.
fn no_live_descendant() -> Result<(), &'static str> {
    loop {
        match wait_timeout(None, 1) {
            Err(Error::NoChild) => return Ok(()),
            Ok(_) => {}
            Err(Error::Timeout) => return Err("durable worker left a live descendant"),
            Err(_) => return Err("durable descendant check"),
        }
    }
}

/// After the durable worker has exited, init still holds the block handle and
/// gives the reader a new handle to the same device with read rights only:
/// the reader's authority is strictly less than the worker's, and the kernel,
/// not the reader, refuses any write through it.
fn run_reader(console: Console, block: u64, step: u64) -> Result<(), &'static str> {
    let reader_block = duplicate(block, RIGHT_READ).map_err(|_| "reader block handle")?;
    let step_cell = Cell::create(step).map_err(|_| "reader step cell")?;
    let extra = [
        SpawnHandleCopy::new(reader_block, RIGHT_READ),
        SpawnHandleCopy::new(step_cell.raw(), RIGHT_READ),
    ];
    let outcome = run_external_with(
        console,
        false,
        program::EXTERNAL_READER,
        &extra,
        EXTERNAL_READER_INPUT,
        Party::Reader,
    );
    close(step_cell.raw()).map_err(|_| "reader step cell close")?;
    close(reader_block).map_err(|_| "reader block handle close")?;
    match outcome? {
        Outcome::Exited(0) => Ok(()),
        _ => Err("durable reader outcome"),
    }
}

fn run_external(console: Console, live: bool) -> Result<(), &'static str> {
    match run_external_with(
        console,
        live,
        program::EXTERNAL_WORKLOAD,
        &[],
        EXTERNAL_INPUT,
        Party::Plain,
    )? {
        Outcome::Exited(0) => Ok(()),
        _ => Err("external workload outcome"),
    }
}

/// Who a workload child is. Durable workers and the reader continue the
/// captured output stream rather than restarting it, and report their
/// outcomes on the console so a host can see every process of the boot.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Party {
    Plain,
    Worker(u64),
    Reader,
}

/// Runs one workload child to completion, feeding it `input`, and returns
/// its outcome.
fn run_external_with(
    console: Console,
    live: bool,
    selected: u64,
    extra: &[SpawnHandleCopy],
    input_bytes: &[u8],
    party: Party,
) -> Result<Outcome, &'static str> {
    let input = Pipe::create().map_err(|_| "external input pipe")?;
    let input_reader = duplicate(input.raw(), RIGHT_READ).map_err(|_| "external input reader")?;
    let input_writer =
        Pipe::from_raw(duplicate(input.raw(), RIGHT_WRITE).map_err(|_| "external input writer")?);
    close(input.raw()).map_err(|_| "external input split")?;

    let output = Pipe::create().map_err(|_| "external output pipe")?;
    let output_reader =
        Pipe::from_raw(duplicate(output.raw(), RIGHT_READ).map_err(|_| "external output reader")?);
    let output_writer =
        duplicate(output.raw(), RIGHT_WRITE).map_err(|_| "external output writer")?;
    close(output.raw()).map_err(|_| "external output split")?;

    if extra.len() > 2 {
        return Err("external extra handles");
    }
    let brokered = matches!(party, Party::Worker(_)) && broker::enabled();
    // A worker that holds the NIC is told so by a startup record, even
    // without a broker channel.
    // So is the external worker of a durable boot, whose record names the
    // stop-only machine handle init grants it.
    let recorded = brokered
        || (matches!(party, Party::Worker(_))
            && (worker_nic() != 0 || fsd_boot() || selected == program::EXTERNAL_WORKLOAD));
    let child = if recorded {
        spawn_worker_brokered(selected, input_reader, extra, output_writer)?
    } else {
        let mut copies = [SpawnHandleCopy::new(0, 0); 4];
        copies[0] = SpawnHandleCopy::new(input_reader, RIGHT_READ);
        copies[1..1 + extra.len()].copy_from_slice(extra);
        copies[1 + extra.len()] = SpawnHandleCopy::console(output_writer, RIGHT_WRITE);
        spawn_many_copy(selected, &copies[..2 + extra.len()])
            .map_err(|_| "external workload spawn")?
    };
    if served() && matches!(party, Party::Worker(_)) {
        unsafe { SERVED_WORKER_HANDLE = child.raw() };
    }
    close(input_reader).map_err(|_| "external parent input reader")?;
    close(output_writer).map_err(|_| "external parent output writer")?;
    let child_pid = info(Some(child))
        .map_err(|_| "external child identity")?
        .pid;
    if matches!(party, Party::Plain | Party::Worker(1))
        && console.write_once(b"EXTERNAL OUTPUT BEGIN encoding=hex\n")
            != Ok(b"EXTERNAL OUTPUT BEGIN encoding=hex\n".len())
    {
        external_abort(child, input_writer, true, output_reader);
        return Err("external output begin");
    }
    match party {
        Party::Plain => {}
        Party::Worker(generation) => {
            let mut line = LineBuffer::new();
            let _ = writeln!(
                line,
                "DURABLE WORKER GENERATION generation={generation} pid={child_pid}"
            );
            external_line(console, &line)?;
        }
        Party::Reader => {
            let mut line = LineBuffer::new();
            let _ = writeln!(line, "DURABLE READER START pid={child_pid} rights=read");
            external_line(console, &line)?;
        }
    }

    // A served boot's worker runs until it ends itself: no deadline.
    let wait_ticks = if matches!(party, Party::Worker(_)) && served() {
        u64::MAX
    } else if matches!(party, Party::Worker(_)) && worker_nic() != 0 {
        net_wait_ticks()
    } else {
        EXTERNAL_WAIT_TICKS
    };
    let deadline = time().saturating_add(wait_ticks);
    // A server worker (NIC, no broker) starts programs itself, and their
    // descendants outlive them (no process-tree kill): init adopts those
    // and must reap them while the worker runs, or each one keeps a
    // process-table entry for the rest of the boot.
    let reaps_orphans = matches!(party, Party::Worker(_))
        && (worker_nic() != 0 || fsd_boot())
        && !broker::enabled();
    let mut next_orphan_reap = 0u64;
    let mut reaped_worker: Option<Outcome> = None;
    let mut worker_end_tick: Option<u64> = None;
    let mut input_offset = 0usize;
    let mut output_offset = unsafe { EXTERNAL_OUTPUT_OFFSET };
    let mut digest = unsafe { EXTERNAL_OUTPUT_DIGEST };
    let mut writer_open = true;
    let mut output_eof = false;
    if live {
        match receive_live_input(console, input_writer, deadline) {
            Ok(received) => {
                input_offset = received;
                writer_open = false;
            }
            Err(error) => {
                external_abort(child, input_writer, true, output_reader);
                return Err(error);
            }
        }
    }
    while !output_eof {
        if served()
            && worker_end_tick.is_some_and(|ended| {
                time() >= ended.saturating_add(SERVED_POST_WORKER_OUTPUT_TICKS)
            })
        {
            external_abort(child, input_writer, writer_open, output_reader);
            return Err("served worker output held after exit");
        }
        if brokered {
            broker::service(console);
        }
        if time() >= deadline {
            external_abort(child, input_writer, writer_open, output_reader);
            return Err("external workload deadline");
        }
        if reaps_orphans && reaped_worker.is_none() && time() >= next_orphan_reap {
            next_orphan_reap = time().saturating_add(ORPHAN_REAP_TICKS);
            match reap_adopted_orphans(console, child_pid) {
                Ok(worker) => {
                    if let Some(outcome) = worker {
                        worker_end_tick = Some(time());
                        unsafe { SERVED_WORKER_HANDLE = 0 };
                        note_served_worker(outcome);
                    }
                    reaped_worker = worker;
                }
                Err(error) => {
                    external_abort(child, input_writer, writer_open, output_reader);
                    return Err(error);
                }
            }
        }
        if !live && input_offset < input_bytes.len() {
            let end = (input_offset + 256).min(input_bytes.len());
            match input_writer.write_timeout(&input_bytes[input_offset..end], 2) {
                Ok(0) => {
                    external_abort(child, input_writer, writer_open, output_reader);
                    return Err("external zero input write");
                }
                Ok(written) => input_offset += written,
                Err(Error::Timeout) => {}
                Err(_) => {
                    external_abort(child, input_writer, writer_open, output_reader);
                    return Err("external input write");
                }
            }
        } else if !live && writer_open {
            if close(input_writer.raw()).is_err() {
                external_abort(child, input_writer, false, output_reader);
                return Err("external input eof");
            }
            writer_open = false;
        }

        let mut output = [0u8; 96];
        match output_reader.read_timeout(&mut output, 2) {
            Ok(0) => output_eof = true,
            Ok(count) => {
                if external_chunk(console, output_offset, &output[..count]).is_err() {
                    external_abort(child, input_writer, writer_open, output_reader);
                    return Err("external output frame");
                }
                if served() {
                    observe_served_ready(&output[..count]);
                }
                for byte in &output[..count] {
                    digest = (digest ^ *byte as u32).wrapping_mul(0x0100_0193);
                }
                output_offset += count;
            }
            Err(Error::Timeout) => {}
            Err(_) => {
                external_abort(child, input_writer, writer_open, output_reader);
                return Err("external output read");
            }
        }
    }
    if writer_open || (!live && input_offset != input_bytes.len()) {
        external_abort(child, input_writer, writer_open, output_reader);
        return Err("external input incomplete");
    }
    let outcome = match reaped_worker {
        Some(outcome) => outcome,
        None => match wait_timeout(Some(child), 500) {
            Ok(outcome) => {
                if served() {
                    unsafe { SERVED_WORKER_HANDLE = 0 };
                    note_served_worker(outcome);
                }
                outcome
            }
            Err(_) => {
                external_abort(child, input_writer, false, output_reader);
                return Err("external workload outcome");
            }
        },
    };
    if brokered {
        // Nothing the worker asked for outlives it.
        broker::service(console);
        broker::close_worker(console);
    }
    close(output_reader.raw()).map_err(|_| "external output close")?;
    unsafe {
        EXTERNAL_OUTPUT_OFFSET = output_offset;
        EXTERNAL_OUTPUT_DIGEST = digest;
    }
    let status = match outcome {
        Outcome::Exited(status) => status as i64,
        Outcome::Faulted { vector, .. } => -(vector as i64) - 1000,
        Outcome::Killed => -1,
    };
    match party {
        Party::Plain => {}
        Party::Worker(generation) => {
            let mut line = LineBuffer::new();
            let _ = writeln!(
                line,
                "DURABLE WORKER OUTCOME generation={generation} pid={child_pid} status={status}"
            );
            external_line(console, &line)?;
        }
        Party::Reader => {
            let mut line = LineBuffer::new();
            let _ = writeln!(
                line,
                "DURABLE READER OUTCOME pid={child_pid} status={status}"
            );
            external_line(console, &line)?;
        }
    }
    if outcome != Outcome::Exited(0) {
        return Ok(outcome);
    }
    // One end record per captured stream: a durable reader continues the
    // worker's stream and ends it.
    if matches!(party, Party::Worker(_)) && EXTERNAL_READER_PRESENT {
        return Ok(outcome);
    }

    let mut end = LineBuffer::new();
    let _ = writeln!(
        end,
        "EXTERNAL OUTPUT END bytes={output_offset} digest={digest:08x}"
    );
    external_line(console, &end)?;
    Ok(outcome)
}

/// The NIC handle a `net` durable boot's worker receives; zero otherwise.
static mut WORKER_NIC: u64 = 0;

/// Reaps every ended child init has adopted, without waiting for live
/// ones. Wait-any can also return the worker itself once it has ended;
/// its outcome is handed back so the caller does not wait for it again.
///
/// The file server stops when the worker, its control channel's last
/// writer, has exited; both can be waiting to be reaped at once, and
/// wait-any may return the server first. So a server that ended fails the
/// boot only if no ended worker follows it: the worker is still running.
fn reap_adopted_orphans(
    console: Console,
    worker_pid: u64,
) -> Result<Option<Outcome>, &'static str> {
    let mut server_ended = false;
    loop {
        match wait_any_timeout(1) {
            Ok(result) if result.pid == worker_pid => return Ok(Some(result.outcome)),
            Ok(result) if fsd_boot() && result.pid == unsafe { FSD_SERVER_PID } => {
                unsafe { FSD_SERVER_OUTCOME = Some(outcome_status(result.outcome)) };
                unsafe { FSD_SERVER_HANDLE = 0 };
                server_ended = true;
            }
            Ok(result) => {
                let mut line = LineBuffer::new();
                let _ = writeln!(line, "INIT ORPHAN REAPED pid={}", result.pid);
                external_line(console, &line)?;
            }
            Err(Error::Timeout) if server_ended => {
                return Err("file server ended while the worker ran");
            }
            Err(Error::Timeout) => return Ok(None),
            Err(_) => return Err("adopted orphan reap"),
        }
    }
}

fn observe_served_ready(bytes: &[u8]) {
    if unsafe { SERVED_READY } {
        return;
    }
    // Init is the only writer and has one task; use a raw pointer to the
    // fixed parser state without taking a reference to mutable static data.
    let probe = core::ptr::addr_of_mut!(SERVED_READY_PROBE);
    if unsafe { (*probe).push(bytes) } {
        unsafe { SERVED_READY = true };
    }
}

fn worker_nic() -> u64 {
    unsafe { WORKER_NIC }
}

/// Starts the durable worker (without the spawn right in broker mode) with a startup
/// record: `[startup, input, block, step, (nic), (request, reply, slots..),
/// console]`. The broker channel is there only when a policy is embedded.
fn spawn_worker_brokered(
    selected: u64,
    input_reader: u64,
    extra: &[SpawnHandleCopy],
    output_writer: u64,
) -> Result<Child, &'static str> {
    use absd_user::broker::{
        ROLE_BLOCK, ROLE_FS_REPLY, ROLE_FS_REQUEST, ROLE_MACHINE, ROLE_NIC, ROLE_STDIN, ROLE_STEP,
        startup_record,
    };
    // An `fsd` worker gets the step cell and channels, never the block.
    let fsd = fsd_boot();
    if extra.len() != if fsd { 1 } else { 2 } {
        return Err("broker worker needs block and step");
    }
    let channel = if broker::enabled() {
        broker::open_worker_channel(extra[0].source)?
    } else {
        broker::ChannelEnds::empty()
    };
    let startup = Pipe::create().map_err(|_| "broker startup pipe")?;
    let startup_reader =
        duplicate(startup.raw(), RIGHT_READ).map_err(|_| "broker startup reader")?;
    let startup_writer =
        Pipe::from_raw(duplicate(startup.raw(), RIGHT_WRITE).map_err(|_| "broker startup writer")?);
    close(startup.raw()).map_err(|_| "broker startup split")?;
    const CAPACITY: usize = broker::CHANNEL_HANDLES + 2 * FSD_CHANNELS;
    let mut copies = [SpawnHandleCopy::new(0, 0); 7 + CAPACITY];
    let mut roles = [(0u8, 0u8); 5 + CAPACITY];
    copies[0] = SpawnHandleCopy::new(startup_reader, RIGHT_READ);
    copies[1] = SpawnHandleCopy::new(input_reader, RIGHT_READ);
    roles[0] = (ROLE_STDIN, 1);
    let mut count = 2;
    let mut role_count = 1;
    if !fsd {
        copies[count] = extra[0];
        roles[role_count] = (ROLE_BLOCK, count as u8);
        count += 1;
        role_count += 1;
    }
    copies[count] = extra[extra.len() - 1];
    roles[role_count] = (ROLE_STEP, count as u8);
    count += 1;
    role_count += 1;
    if worker_nic() != 0 {
        copies[count] = SpawnHandleCopy::new(worker_nic(), RIGHT_READ | RIGHT_WRITE);
        roles[role_count] = (ROLE_NIC, count as u8);
        count += 1;
        role_count += 1;
    }
    // A qualification durable worker may stop the machine at a named point
    // (its crash matrices do): a copy with the stop right and nothing else.
    // An `fsd` boot's worker (sshd), served or not, gets no machine handle.
    let machine = unsafe { MACHINE };
    if !fsd && machine != 0 {
        copies[count] = SpawnHandleCopy::new(machine, MACHINE_RIGHT_STOP);
        roles[role_count] = (ROLE_MACHINE, count as u8);
        count += 1;
        role_count += 1;
    }
    for position in 0..channel.count {
        let role = channel.roles[position];
        let rights = if role == absd_user::broker::ROLE_REQUEST
            || role == absd_user::broker::ROLE_SLOT_STDIN
        {
            RIGHT_WRITE
        } else {
            RIGHT_READ
        };
        copies[count] = SpawnHandleCopy::new(channel.handles[position], rights);
        roles[role_count] = (role, count as u8);
        count += 1;
        role_count += 1;
    }
    if fsd {
        for (request, reply) in unsafe { FSD_CLIENT } {
            copies[count] = SpawnHandleCopy::new(request, RIGHT_WRITE);
            roles[role_count] = (ROLE_FS_REQUEST, count as u8);
            copies[count + 1] = SpawnHandleCopy::new(reply, RIGHT_READ);
            roles[role_count + 1] = (ROLE_FS_REPLY, count as u8 + 1);
            count += 2;
            role_count += 2;
        }
    }
    copies[count] = SpawnHandleCopy::console(output_writer, RIGHT_WRITE);
    count += 1;
    // Only broker mode withholds the spawn right (docs/BROKER.md). A NIC
    // worker without a policy keeps it, as every other unbrokered worker
    // does: a server (sshd) starts its session programs from the
    // filesystem itself (docs/PROCESS-STARTUP.md).
    let flags = if broker::enabled() {
        absd_abi::syscall::SPAWN_NO_SPAWN
    } else {
        0
    };
    let spawned = spawn_many_copy(selected | flags, &copies[..count]);
    close(startup_reader).map_err(|_| "broker startup reader close")?;
    channel.close();
    if fsd {
        // Init keeps no end of any channel: the worker's copies are the
        // clients' only source, so the server can count them.
        for (request, reply) in unsafe { FSD_CLIENT } {
            close(request).map_err(|_| "fsd client end close")?;
            close(reply).map_err(|_| "fsd client end close")?;
        }
        unsafe { FSD_CLIENT = [(0, 0); FSD_CHANNELS] };
    }
    let child = spawned.map_err(|_| "external workload spawn")?;
    if broker::enabled() {
        broker::set_owner(channel.requester, child);
    }
    let mut record = [0u8; 512];
    let length = startup_record(&mut record, &roles[..role_count], &[0, 0])
        .ok_or("broker startup record")?;
    startup_writer
        .write_all(&record[..length])
        .map_err(|_| "broker startup write")?;
    close(startup_writer.raw()).map_err(|_| "broker startup close")?;
    Ok(child)
}

/// A `net-probe` boot: the kernel's NIC qualification program gets the NIC
/// init was granted, and `step` selects its phase (docs/NETWORK.md).
fn run_net_probe(console: Console, nic: u64, step: u64) -> Result<(), &'static str> {
    if nic == 0 {
        return Err("no NIC");
    }
    reserve_multicore_service()?;
    let child = spawn_with(program::NIC_PROBE, nic, step).map_err(|_| "nic probe spawn")?;
    let outcome = wait(Some(child)).map_err(|_| "nic probe wait")?;
    let _ = console.line(format_args!("NET PROBE OUTCOME {outcome:?}\n"));
    match outcome {
        Outcome::Exited(0) => Ok(()),
        _ => Err("nic probe outcome"),
    }
}

/// Captured-output framing continues across durable worker generations.
static mut EXTERNAL_OUTPUT_OFFSET: usize = 0;
static mut EXTERNAL_OUTPUT_DIGEST: u32 = 0x811c_9dc5;

fn bootstrap_child(console: Console, selected: u64) -> Result<(), &'static str> {
    let child = spawn(selected).map_err(|_| "bootstrap spawn")?;
    let selected_pid = info(Some(child))
        .map_err(|_| "bootstrap child identity")?
        .pid;
    // The child may print a non-newline prompt before init resumes after
    // spawn. Start a fresh line so this acceptance record stays unambiguous.
    let _ = console.write_str("\nINIT SPAWN OK\n");
    // Wait-any lets PID 1 drain adopted terminal descendants even while the
    // selected program remains live. The returned PID identifies what was
    // reaped; it is not a process handle and therefore not info/kill authority.
    let mut selected_done = false;
    loop {
        match wait_any_timeout(SUPERVISOR_WAIT_TICKS) {
            Ok(result) if result.pid == selected_pid => {
                if result.outcome != Outcome::Exited(0) {
                    return Err("bootstrap child outcome");
                }
                selected_done = true;
            }
            Ok(_) => {}
            Err(Error::Timeout) => {}
            Err(Error::NoChild) if selected_done => break,
            Err(Error::NoChild) => return Err("bootstrap child disappeared"),
            Err(_) => return Err("bootstrap orphan drain"),
        }
    }
    let _ = console.write_str("INIT REAP OK\n");
    Ok(())
}

/// One fatal hostile case: the probe child must die of exactly the exception
/// the architecture and the page tables derive for its act (see the table in
/// docs/HOSTILE-USERSPACE.md); `address` pins CR2 where it is deterministic.
struct HostileCase {
    arg: u64,
    name: &'static str,
    vector: u64,
    error: u64,
    address: Option<u64>,
}

const HOSTILE_SUPERVISOR: u64 = 0x10_0000;
const HOSTILE_GAP: u64 = 0x0000_0081_0000_0000;

const HOSTILE_CASES: &[HostileCase] = &[
    HostileCase {
        arg: 1,
        name: "READ SUPERVISOR",
        vector: VECTOR_PAGE_FAULT,
        error: 0x5,
        address: Some(HOSTILE_SUPERVISOR),
    },
    HostileCase {
        arg: 2,
        name: "WRITE SUPERVISOR",
        vector: VECTOR_PAGE_FAULT,
        error: 0x7,
        address: Some(HOSTILE_SUPERVISOR),
    },
    HostileCase {
        arg: 3,
        name: "EXEC SUPERVISOR",
        vector: VECTOR_PAGE_FAULT,
        error: 0x15,
        address: Some(HOSTILE_SUPERVISOR),
    },
    HostileCase {
        arg: 4,
        name: "EXEC NX HEAP",
        vector: VECTOR_PAGE_FAULT,
        error: 0x15,
        address: None,
    },
    HostileCase {
        arg: 5,
        name: "WRITE TEXT",
        vector: VECTOR_PAGE_FAULT,
        error: 0x7,
        address: None,
    },
    HostileCase {
        arg: 6,
        name: "READ NULL SUPERVISOR",
        vector: VECTOR_PAGE_FAULT,
        error: 0x5,
        address: Some(0),
    },
    HostileCase {
        arg: 7,
        name: "READ GAP",
        vector: VECTOR_PAGE_FAULT,
        error: 0x4,
        address: Some(HOSTILE_GAP),
    },
    HostileCase {
        arg: 8,
        name: "DIVIDE ZERO",
        vector: VECTOR_DIVIDE_ERROR,
        error: 0,
        address: None,
    },
    HostileCase {
        arg: 9,
        name: "IO INSTRUCTION",
        vector: VECTOR_GENERAL_PROTECTION,
        error: 0,
        address: None,
    },
    HostileCase {
        arg: 10,
        name: "LIDT",
        vector: VECTOR_GENERAL_PROTECTION,
        error: 0,
        address: None,
    },
    HostileCase {
        // `int3` from CPL 3 through the DPL-0 vector-3 gate fails the
        // software-interrupt DPL check: #GP with the IDT-referencing error
        // code (vector << 3) | 0b010. The act still terminates the task.
        arg: 11,
        name: "INT3",
        vector: VECTOR_GENERAL_PROTECTION,
        error: 0x1a,
        address: None,
    },
    HostileCase {
        // Intel SDM derives #GP(0) for a noncanonical data read, and real
        // hardware is expected to deliver that. The qualified execution
        // environment (QEMU 8.2.2 TCG) instead performs the page walk:
        // the address's PML4 index (bits 47:39) is 0, and every user root
        // shares supervisor PML4 entry 0 (`src/vm.rs`), so the walk lands
        // on present supervisor mappings and reports a supervisor
        // protection #PF (error 0x5) with CR2 set to the address. Both
        // outcomes contain the act and terminate the task; the pin is the
        // TCG-derived one, and the SDM #GP on physical hardware remains
        // unproven (docs/HOSTILE-USERSPACE.md).
        arg: 12,
        name: "NONCANONICAL",
        vector: VECTOR_PAGE_FAULT,
        error: 0x5,
        address: Some(0x8000_0000_0000_0000),
    },
];

/// Crash/relaunch cycles (divide-by-zero) that must each fault identically.
const HOSTILE_CRASH_CYCLES: u32 = 32;
/// Probe case selector of the invalid-syscall flood.
const HOSTILE_CASE_FLOOD: u64 = 13;
/// Bound on every witness wait; a starved witness fails the boot.
const HOSTILE_WITNESS_TICKS: u64 = 10_000;
/// Probe case selectors of the state-machine spike (docs/HOSTILE-USERSPACE.md).
const HOSTILE_CASE_STATE_HANDLES: u64 = 14;
const HOSTILE_CASE_FORK_BOMB: u64 = 15;
const HOSTILE_CASE_VM_CHURN: u64 = 16;
const HOSTILE_CASE_EXIT_MAPPED: u64 = 17;
const HOSTILE_CASE_KILL_MAPPED: u64 = 18;
const HOSTILE_CASE_CELLS_EXHAUSTED: u64 = 19;
const HOSTILE_CASE_PIPES_EXHAUSTED: u64 = 20;
const HOSTILE_CASE_CHURN: u64 = 21;
const HOSTILE_CASE_CHURN_FOREVER: u64 = 22;
const HOSTILE_CASE_FAULT_WITH_CHILD_AND_PIPE: u64 = 23;
const HOSTILE_CASE_MIDDLE_WAITER: u64 = 24;
const HOSTILE_CASE_BLOCKED_READER: u64 = 25;
/// Ticks init lets the kill-mapped and churn-forever probes run before the
/// kill arrives: long enough to own their state, short enough to stay quick.
const HOSTILE_KILL_DELAY_TICKS: u64 = 50;
/// Bound of the timed wait that must expire against a never-ending child.
const HOSTILE_TIMEOUT_TICKS: u64 = 50;

/// Free/allocated frame counts as one comparable value for the reclamation
/// oracles of the state phases.
fn frame_counts() -> Result<(u64, u64), &'static str> {
    let stats = frame_stats().map_err(|_| "hostile frame stats")?;
    Ok((stats.free_frames, stats.allocated_frames))
}

/// Collects one adopted child with the wanted outcome. Witness #1 has been
/// terminal since phase one without being reaped, so any `wait_any` can
/// return it first; record that and keep waiting.
fn reap_adoptee(
    witness_pid: u64,
    witness_reaped: &mut bool,
    expected: Outcome,
    step: &'static str,
) -> Result<(), &'static str> {
    loop {
        match wait_any_timeout(HOSTILE_WITNESS_TICKS) {
            Ok(result) if result.pid == witness_pid => {
                if *witness_reaped || result.outcome != Outcome::Exited(0) {
                    return Err(step);
                }
                *witness_reaped = true;
            }
            Ok(result) if result.outcome == expected => return Ok(()),
            _ => return Err(step),
        }
    }
}

/// The hostile-userspace qualification boot (docs/HOSTILE-USERSPACE.md): one
/// well-behaved witness must stay schedulable across a non-fatal abuse
/// battery, a table of fatal cases, a crash/relaunch loop, and a syscall
/// flood that init ends with `kill`.
fn run_hostile(console: Console) -> Result<(), &'static str> {
    // With no children at all, waiting for one is refused, not parked.
    if wait_any() != Err(Error::NoChild) {
        return Err("hostile empty wait");
    }

    let witness = spawn(program::HELLO_B).map_err(|_| "hostile witness spawn")?;
    // Witness #1 stays terminal-but-unreaped until the end of the boot, so
    // any `wait_any` in the state phases can collect it first; its PID tells
    // it apart from the adopted children those phases actually wait for.
    let witness_pid = info(Some(witness)).map_err(|_| "hostile witness info")?.pid;
    let mut witness_reaped = false;

    let battery = spawn_with(program::HOSTILE_PROBE, 0, 0).map_err(|_| "hostile battery spawn")?;
    match wait(Some(battery)).map_err(|_| "hostile battery wait")? {
        Outcome::Exited(0) => {}
        _ => return Err("hostile battery outcome"),
    }
    let _ = console.write_str("HOSTILE SYS ABUSE OK\n");

    for case in HOSTILE_CASES {
        let child =
            spawn_with(program::HOSTILE_PROBE, 0, case.arg).map_err(|_| "hostile case spawn")?;
        match wait(Some(child)).map_err(|_| "hostile case wait")? {
            Outcome::Faulted {
                vector,
                address,
                error,
            } if vector == case.vector
                && error == case.error
                && case.address.is_none_or(|expected| expected == address) => {}
            _ => return Err(case.name),
        }
        let _ = console.line(format_args!("HOSTILE {} OK\n", case.name));
    }

    // Repeated crash/relaunch cycles must not destabilize the kernel: each
    // fresh process faults on the same vector and is reaped completely.
    for _ in 0..HOSTILE_CRASH_CYCLES {
        let child = spawn_with(program::HOSTILE_PROBE, 0, 8).map_err(|_| "hostile crash spawn")?;
        match wait(Some(child)).map_err(|_| "hostile crash wait")? {
            Outcome::Faulted {
                vector: VECTOR_DIVIDE_ERROR,
                ..
            } => {}
            _ => return Err("hostile crash cycle outcome"),
        }
    }
    let _ = console.write_str("HOSTILE CRASH CYCLES OK\n");

    // A syscall flood from one task must not starve a well-behaved task: the
    // second witness finishes while the flood runs, then init kills and
    // reaps the flood.
    let flood = spawn_with(program::HOSTILE_PROBE, 0, HOSTILE_CASE_FLOOD)
        .map_err(|_| "hostile flood spawn")?;
    let second = spawn(program::HELLO_B).map_err(|_| "hostile second witness spawn")?;
    match wait_timeout(Some(second), HOSTILE_WITNESS_TICKS)
        .map_err(|_| "hostile second witness wait")?
    {
        Outcome::Exited(0) => {}
        _ => return Err("hostile flood witness outcome"),
    }
    kill(flood).map_err(|_| "hostile flood kill")?;
    match wait(Some(flood)).map_err(|_| "hostile flood wait")? {
        Outcome::Killed => {}
        _ => return Err("hostile flood outcome"),
    }
    let _ = console.write_str("HOSTILE FLOOD WITNESS OK\n");

    // S1: handle and object lifetime abuse — duplicates, stale and crafted
    // values, rights narrowing, bounded transfers, and a full handle table.
    let state = spawn_with(program::HOSTILE_PROBE, 0, HOSTILE_CASE_STATE_HANDLES)
        .map_err(|_| "hostile state spawn")?;
    expect_exit(state, 0, "hostile state handles outcome")?;
    let _ = console.write_str("HOSTILE STATE HANDLES OK\n");

    // S2: process lifecycle. The process table fails closed at its bound and
    // recovers; kill/wait/info edges around reaping stay exact.
    let bomb = spawn_with(program::HOSTILE_PROBE, 0, HOSTILE_CASE_FORK_BOMB)
        .map_err(|_| "hostile bomb spawn")?;
    expect_exit(bomb, 0, "hostile fork bomb outcome")?;
    // Positive control: a fresh spawn works immediately after the bomb.
    let control = spawn(program::EXIT7).map_err(|_| "hostile post-bomb spawn")?;
    expect_exit(control, 7, "hostile post-bomb outcome")?;

    // Kill landing on a live child: no yield sits between spawn and kill, so
    // normally the child has never been scheduled; but the PIT can preempt
    // init in that window and let exit7 run to its own exit first, which the
    // kernel correctly answers with a no-op kill and `Exited(7)`. Retry until
    // the kill demonstrably arrived while the child was alive; the bounded
    // retry keeps the kill/refusal counters exact either way.
    let mut lost_race = 0u32;
    let child = loop {
        let child = spawn(program::EXIT7).map_err(|_| "hostile pre-run spawn")?;
        kill(child).map_err(|_| "hostile pre-run kill")?;
        // A second kill of the terminal child is a harmless no-op.
        kill(child).map_err(|_| "hostile double kill")?;
        match wait(Some(child)).map_err(|_| "hostile pre-run wait")? {
            Outcome::Killed => break child,
            Outcome::Exited(7) => {
                lost_race += 1;
                if lost_race > 100 {
                    return Err("hostile pre-run race");
                }
            }
            _ => return Err("hostile pre-run outcome"),
        }
    };
    // Reaping consumed the handle: every further use of it is refused.
    if kill(child) != Err(Error::BadHandle) {
        return Err("hostile kill after reap");
    }
    if wait(Some(child)) != Err(Error::BadHandle) {
        return Err("hostile double wait");
    }
    if info(Some(child)).map(|_| ()) != Err(Error::BadHandle) {
        return Err("hostile info after reap");
    }

    // A narrowed wait-only duplicate cannot kill; the original can, and
    // reaping consumes every duplicate of the child's handle.
    let child = spawn_with(program::SLEEPER, 0, u64::MAX).map_err(|_| "hostile narrowed spawn")?;
    let narrowed = duplicate(child.raw(), RIGHT_WAIT).map_err(|_| "hostile narrowed dup")?;
    if kill(Child::from_raw(narrowed)) != Err(Error::Rights) {
        return Err("hostile narrowed kill");
    }
    kill(child).map_err(|_| "hostile narrowed original")?;
    match wait(Some(child)).map_err(|_| "hostile narrowed wait")? {
        Outcome::Killed => {}
        _ => return Err("hostile narrowed outcome"),
    }
    if close(narrowed) != Err(Error::BadHandle) {
        return Err("hostile narrowed after reap");
    }

    // A bounded wait on a live child times out and leaves it alive.
    let child = spawn_with(program::SLEEPER, 0, u64::MAX).map_err(|_| "hostile timeout spawn")?;
    if wait_timeout(Some(child), HOSTILE_TIMEOUT_TICKS) != Err(Error::Timeout) {
        return Err("hostile wait timeout");
    }
    if info(Some(child)).map_err(|_| "hostile timeout info")?.state == INFO_STATE_TERMINAL {
        return Err("hostile timeout state");
    }
    kill(child).map_err(|_| "hostile timeout kill")?;
    match wait(Some(child)).map_err(|_| "hostile timeout wait")? {
        Outcome::Killed => {}
        _ => return Err("hostile timeout outcome"),
    }

    // A faulting parent releases its transferred pipe end and orphans its own
    // child: EOF on the pipe, and init adopts and reaps the sleeper.
    let pipe = Pipe::create().map_err(|_| "hostile case23 pipe")?;
    let writer = duplicate(pipe.raw(), RIGHT_WRITE).map_err(|_| "hostile case23 writer")?;
    let reader = duplicate(pipe.raw(), RIGHT_READ).map_err(|_| "hostile case23 reader")?;
    close(pipe.raw()).map_err(|_| "hostile case23 close")?;
    let child = spawn_with(
        program::HOSTILE_PROBE,
        writer,
        HOSTILE_CASE_FAULT_WITH_CHILD_AND_PIPE,
    )
    .map_err(|_| "hostile case23 spawn")?;
    close(writer).map_err(|_| "hostile case23 close writer")?;
    match wait(Some(child)).map_err(|_| "hostile case23 wait")? {
        Outcome::Faulted {
            vector: VECTOR_DIVIDE_ERROR,
            ..
        } => {}
        _ => return Err("hostile case23 outcome"),
    }
    let mut byte = [0u8; 1];
    if Pipe::from_raw(reader).read_once(&mut byte) != Ok(0) {
        return Err("hostile case23 eof");
    }
    close(reader).map_err(|_| "hostile case23 close reader")?;
    reap_adoptee(
        witness_pid,
        &mut witness_reaped,
        Outcome::Exited(0),
        "hostile case23 adoptee",
    )?;

    // A parent killed while blocked in `wait`: its child is adopted.
    let child = spawn_with(program::HOSTILE_PROBE, 0, HOSTILE_CASE_MIDDLE_WAITER)
        .map_err(|_| "hostile case24 spawn")?;
    expect_waiting(child, "hostile case24 waiting")?;
    kill(child).map_err(|_| "hostile case24 kill")?;
    match wait(Some(child)).map_err(|_| "hostile case24 wait")? {
        Outcome::Killed => {}
        _ => return Err("hostile case24 outcome"),
    }
    reap_adoptee(
        witness_pid,
        &mut witness_reaped,
        Outcome::Exited(0),
        "hostile case24 adoptee",
    )?;

    // A process killed while blocked in a pipe read releases its end: the
    // surviving writer sees a broken pipe, not a hang.
    let pipe = Pipe::create().map_err(|_| "hostile case25 pipe")?;
    let writer = duplicate(pipe.raw(), RIGHT_WRITE).map_err(|_| "hostile case25 writer")?;
    let reader = duplicate(pipe.raw(), RIGHT_READ).map_err(|_| "hostile case25 reader")?;
    close(pipe.raw()).map_err(|_| "hostile case25 close")?;
    let child = spawn_with(program::HOSTILE_PROBE, reader, HOSTILE_CASE_BLOCKED_READER)
        .map_err(|_| "hostile case25 spawn")?;
    close(reader).map_err(|_| "hostile case25 close reader")?;
    expect_waiting(child, "hostile case25 waiting")?;
    kill(child).map_err(|_| "hostile case25 kill")?;
    match wait(Some(child)).map_err(|_| "hostile case25 wait")? {
        Outcome::Killed => {}
        _ => return Err("hostile case25 outcome"),
    }
    if Pipe::from_raw(writer).write_once(&[7u8]) != Err(Error::BrokenPipe) {
        return Err("hostile case25 broken pipe");
    }
    close(writer).map_err(|_| "hostile case25 close writer")?;
    let _ = console.write_str("HOSTILE STATE LIFECYCLE OK\n");

    // S3: VM lifetime. Churn returns every frame it allocates; a faulting or
    // killed process leaves nothing mapped. The frame counts pin reclamation.
    let before = frame_counts()?;
    let churn = spawn_with(program::HOSTILE_PROBE, 0, HOSTILE_CASE_VM_CHURN)
        .map_err(|_| "hostile vm churn spawn")?;
    expect_exit(churn, 0, "hostile vm churn outcome")?;
    if frame_counts()? != before {
        return Err("hostile vm churn frames");
    }
    let before = frame_counts()?;
    let mapped = spawn_with(program::HOSTILE_PROBE, 0, HOSTILE_CASE_EXIT_MAPPED)
        .map_err(|_| "hostile exit-mapped spawn")?;
    match wait(Some(mapped)).map_err(|_| "hostile exit-mapped wait")? {
        Outcome::Faulted {
            vector: VECTOR_DIVIDE_ERROR,
            ..
        } => {}
        _ => return Err("hostile exit-mapped outcome"),
    }
    if frame_counts()? != before {
        return Err("hostile exit-mapped frames");
    }
    let before = frame_counts()?;
    let mapped = spawn_with(program::HOSTILE_PROBE, 0, HOSTILE_CASE_KILL_MAPPED)
        .map_err(|_| "hostile kill-mapped spawn")?;
    sleep(HOSTILE_KILL_DELAY_TICKS);
    kill(mapped).map_err(|_| "hostile kill-mapped kill")?;
    match wait(Some(mapped)).map_err(|_| "hostile kill-mapped wait")? {
        Outcome::Killed => {}
        _ => return Err("hostile kill-mapped outcome"),
    }
    if frame_counts()? != before {
        return Err("hostile kill-mapped frames");
    }
    let _ = console.write_str("HOSTILE STATE VM OK\n");

    // S4: bounded object tables fail closed at capacity, and a process that
    // exits still holding a full table drains every object it held.
    for (case, step) in [
        (HOSTILE_CASE_CELLS_EXHAUSTED, "hostile cells outcome"),
        (HOSTILE_CASE_PIPES_EXHAUSTED, "hostile pipes outcome"),
    ] {
        let before = frame_counts()?;
        let child = spawn_with(program::HOSTILE_PROBE, 0, case).map_err(|_| step)?;
        expect_exit(child, 0, step)?;
        if frame_counts()? != before {
            return Err("hostile objects frames");
        }
    }
    // Positive control: both object tables work again at once.
    let pipe = Pipe::create().map_err(|_| "hostile objects pipe")?;
    if pipe.write_once(&[0xa5; 4]) != Ok(4) {
        return Err("hostile objects pipe write");
    }
    let mut back = [0u8; 4];
    if pipe.read_once(&mut back) != Ok(4) || back != [0xa5; 4] {
        return Err("hostile objects pipe read");
    }
    close(pipe.raw()).map_err(|_| "hostile objects pipe close")?;
    let cell = Cell::create(1).map_err(|_| "hostile objects cell")?;
    if cell.transition(0, 2) != Ok(1) {
        return Err("hostile objects cell transition");
    }
    if cell.read() != Ok((1, 2)) {
        return Err("hostile objects cell read");
    }
    close(cell.raw()).map_err(|_| "hostile objects cell close")?;
    let _ = console.write_str("HOSTILE STATE OBJECTS OK\n");

    // S5: an innocent witness makes bounded progress while a hostile worker
    // churns spawn/map/pipe/cell cycles with no yields, preempted by the PIT;
    // the unbounded churner is then killed mid-sequence and strays drain.
    let churn_witness = spawn(program::ISOLATION).map_err(|_| "hostile churn witness spawn")?;
    let churner = spawn_with(program::HOSTILE_PROBE, 0, HOSTILE_CASE_CHURN)
        .map_err(|_| "hostile churn spawn")?;
    match wait_timeout(Some(churn_witness), HOSTILE_WITNESS_TICKS)
        .map_err(|_| "hostile churn witness wait")?
    {
        Outcome::Exited(0) => {}
        _ => return Err("hostile churn witness outcome"),
    }
    match wait_timeout(Some(churner), HOSTILE_WITNESS_TICKS).map_err(|_| "hostile churn wait")? {
        Outcome::Exited(0) => {}
        _ => return Err("hostile churn outcome"),
    }
    let forever = spawn_with(program::HOSTILE_PROBE, 0, HOSTILE_CASE_CHURN_FOREVER)
        .map_err(|_| "hostile churn-forever spawn")?;
    sleep(HOSTILE_KILL_DELAY_TICKS);
    kill(forever).map_err(|_| "hostile churn-forever kill")?;
    match wait(Some(forever)).map_err(|_| "hostile churn-forever wait")? {
        Outcome::Killed => {}
        _ => return Err("hostile churn-forever outcome"),
    }
    // Adopted strays of the killed churner (an in-flight exit7 child) finish
    // on their own and drain here; witness #1 may surface first.
    loop {
        match wait_any_timeout(HOSTILE_WITNESS_TICKS) {
            Ok(result) if result.pid == witness_pid => {
                if witness_reaped || result.outcome != Outcome::Exited(0) {
                    return Err("hostile drain witness");
                }
                witness_reaped = true;
            }
            Ok(result) if result.outcome == Outcome::Exited(7) => {}
            Err(Error::NoChild) => break,
            _ => return Err("hostile drain outcome"),
        }
    }
    let _ = console.write_str("HOSTILE STATE CHURN OK\n");

    // The witness present since before every hostile act must have finished
    // cleanly by now: the scheduler kept making progress throughout. (A
    // `wait_any` in the state phases may already have collected it.)
    if !witness_reaped {
        match wait_timeout(Some(witness), HOSTILE_WITNESS_TICKS)
            .map_err(|_| "hostile witness wait")?
        {
            Outcome::Exited(0) => {}
            _ => return Err("hostile witness outcome"),
        }
    }
    let _ = console.write_str("HOSTILE WITNESS OK\n");
    Ok(())
}

fn run(console: Console, reserve: usize) -> Result<(), &'static str> {
    // Phase 1: the demonstration programs.
    let a = spawn(program::HELLO_A).map_err(|_| "spawn hello-a")?;
    let b = spawn(program::HELLO_B).map_err(|_| "spawn hello-b")?;
    let seven = spawn(program::EXIT7).map_err(|_| "spawn exit7")?;
    let faulty = spawn(program::FAULT).map_err(|_| "spawn fault")?;
    expect_exit(a, 0, "hello-a outcome")?;
    expect_exit(b, 0, "hello-b outcome")?;
    expect_exit(seven, 7, "exit7 outcome")?;
    expect_fault(faulty, "fault outcome")?;

    // Other exception classes are process failures too, reported by vector.
    let trap = spawn(program::TRAP).map_err(|_| "spawn trap")?;
    let privileged = spawn(program::PRIVILEGED).map_err(|_| "spawn privileged")?;
    match wait(Some(trap)) {
        Ok(Outcome::Faulted {
            vector: VECTOR_INVALID_OPCODE,
            error: 0,
            ..
        }) => {}
        _ => return Err("trap outcome"),
    }
    match wait(Some(privileged)) {
        Ok(Outcome::Faulted {
            vector: VECTOR_GENERAL_PROTECTION,
            error: 0,
            ..
        }) => {}
        _ => return Err("privileged outcome"),
    }

    // Anonymous memory: map/unmap cycles, an exact fault on an unmapped
    // page, and the implicit guard page below the user stack.
    let heap = spawn(program::HEAP).map_err(|_| "spawn heap")?;
    expect_exit(heap, 0, "heap outcome")?;
    let alloc_probe = spawn(program::ALLOC_PROBE).map_err(|_| "spawn alloc probe")?;
    expect_exit(alloc_probe, 0, "alloc probe outcome")?;
    let isolation_a = spawn(program::ISOLATION).map_err(|_| "spawn isolation a")?;
    let isolation_b = spawn(program::ISOLATION).map_err(|_| "spawn isolation b")?;
    expect_exit(isolation_a, 0, "isolation a outcome")?;
    expect_exit(isolation_b, 0, "isolation b outcome")?;
    let _ = console.write_str("ADDRESS SPACE ISOLATION OK\n");
    let stack_grow = spawn(program::STACK_GROW).map_err(|_| "spawn stack-grow")?;
    expect_exit(stack_grow, 0, "stack-grow outcome")?;
    let stack_jump = spawn(program::STACK_JUMP).map_err(|_| "spawn stack-jump")?;
    match wait(Some(stack_jump)) {
        Ok(Outcome::Faulted {
            vector: VECTOR_PAGE_FAULT,
            address,
            error: 0x6,
        }) if address == USER_STACK_TOP - 4 * 4096 => {}
        _ => return Err("stack-jump outcome"),
    }
    let _ = console.write_str("STACK GROW ISOLATION OK\n");
    let unmapped = spawn(program::UNMAPPED).map_err(|_| "spawn unmapped")?;
    match wait(Some(unmapped)) {
        Ok(Outcome::Faulted {
            vector: VECTOR_PAGE_FAULT,
            address,
            error: 0x4,
        }) if address == USER_HEAP_BASE => {}
        _ => return Err("unmapped outcome"),
    }
    let overflow = spawn(program::OVERFLOW).map_err(|_| "spawn overflow")?;
    match wait(Some(overflow)) {
        Ok(Outcome::Faulted {
            vector: VECTOR_PAGE_FAULT,
            address,
            error: 0x6,
        }) if (USER_STACK_BASE - 4096..USER_STACK_BASE).contains(&address) => {}
        _ => return Err("overflow outcome"),
    }

    // The first native object: conditional transitions on a kernel cell.
    let cell = spawn(program::CELL).map_err(|_| "spawn cell")?;
    expect_exit(cell, 0, "cell outcome")?;

    // Handle transfer: three children race on one cell handed over at
    // spawn. Every successful transition adds exactly one, so the final
    // version and value are known regardless of interleaving.
    let shared = Cell::create(0).map_err(|_| "create shared cell")?;
    match spawn_with(program::SHARED, shared.raw() + 1, 1) {
        Err(Error::BadHandle) => {}
        _ => return Err("spawn with bogus handle"),
    }
    let racers = [
        spawn_with(program::SHARED, shared.raw(), 1).map_err(|_| "spawn racer")?,
        spawn_with(program::SHARED, shared.raw(), 2).map_err(|_| "spawn racer")?,
        spawn_with(program::SHARED, shared.raw(), 3).map_err(|_| "spawn racer")?,
    ];
    for racer in racers {
        expect_exit(racer, 0, "racer outcome")?;
    }
    if shared.read() != Ok((150, 150)) {
        return Err("shared cell state");
    }
    // Rights reduction: a child holding a read-only duplicate cannot move
    // the cell, and the reference it held is released when it exits.
    let readonly = duplicate(shared.raw(), RIGHT_READ).map_err(|_| "duplicate read-only")?;
    let reader = spawn_with(program::READONLY, readonly, 0).map_err(|_| "spawn readonly")?;
    expect_exit(reader, 0, "readonly outcome")?;
    if shared.read() != Ok((150, 150)) {
        return Err("read-only child changed the cell");
    }
    close(readonly).map_err(|_| "close read-only")?;
    close(shared.raw()).map_err(|_| "close shared cell")?;

    verify_multi_handle_spawn(console)?;
    verify_pipe_cell_composition(console)?;
    verify_pipe_info(console)?;
    verify_input_stream(console)?;
    verify_handle_lifetime_stress(console)?;

    // Blocking on change: a watcher sleeps on the cell while init advances
    // it to the stop mark, and a wait on an already-moved version returns
    // at once.
    let watched = Cell::create(0).map_err(|_| "create watched cell")?;
    let watcher = spawn_with(program::WATCHER, watched.raw(), 0).map_err(|_| "spawn watcher")?;
    let mut version = 0;
    for step in 1..=100u64 {
        version = watched
            .transition(version, step)
            .map_err(|_| "advance watched cell")?;
        if step % 10 == 0 {
            yield_now();
        }
    }
    if watched.wait_change(0) != Ok(100) {
        return Err("wait on moved cell");
    }
    expect_exit(watcher, 0, "watcher outcome")?;
    close(watched.raw()).map_err(|_| "close watched cell")?;

    // Pipes: a child streams numbered lines through a write end; init
    // reads until the child's exit drops the last writer. The stream is
    // larger than the pipe, so both sides block and wake along the way.
    let both = Pipe::create().map_err(|_| "create pipe")?;
    let reading = Pipe::from_raw(duplicate(both.raw(), RIGHT_READ).map_err(|_| "dup read end")?);
    let writing = duplicate(both.raw(), RIGHT_WRITE).map_err(|_| "dup write end")?;
    close(both.raw()).map_err(|_| "close both ends")?;
    let piper = spawn_with(program::PIPER, writing, PIPER_LINES).map_err(|_| "spawn piper")?;
    close(writing).map_err(|_| "close init write end")?;
    let mut total = 0;
    let mut newlines = 0;
    let mut expected = 0u64;
    let mut carry = [0u8; 16];
    let mut carried = 0;
    loop {
        let mut chunk = [0u8; 100];
        let count = reading.read_once(&mut chunk).map_err(|_| "pipe read")?;
        if count == 0 {
            break;
        }
        total += count;
        for &byte in &chunk[..count] {
            carry[carried] = byte;
            carried += 1;
            if byte == b'\n' {
                // Every line must arrive whole, in order, exactly once.
                let mut line = *b"piper: line 000\n";
                line[12] = b'0' + (expected / 100 % 10) as u8;
                line[13] = b'0' + (expected / 10 % 10) as u8;
                line[14] = b'0' + (expected % 10) as u8;
                if carry[..carried] != line {
                    return Err("pipe line content");
                }
                expected += 1;
                newlines += 1;
                carried = 0;
            }
        }
    }
    if newlines != PIPER_LINES || total != (PIPER_LINES * 16) as usize || carried != 0 {
        return Err("pipe stream length");
    }
    expect_exit(piper, 0, "piper outcome")?;
    // Reading from a drained pipe with no writer stays at end of file.
    if reading.read_once(&mut [0u8; 8]) != Ok(0) {
        return Err("pipe eof");
    }
    close(reading.raw()).map_err(|_| "close read end")?;
    // A write with no reader left is refused, not blocked.
    let lonely = Pipe::create().map_err(|_| "create lonely pipe")?;
    let writer = Pipe::from_raw(duplicate(lonely.raw(), RIGHT_WRITE).map_err(|_| "dup lonely")?);
    close(lonely.raw()).map_err(|_| "close lonely")?;
    match writer.write_once(b"x") {
        Err(Error::BrokenPipe) => {}
        _ => return Err("write without reader"),
    }
    close(writer.raw()).map_err(|_| "close lonely writer")?;
    let _ = console.write_str("init: pipe stream verified\n");

    // Output capture: a child spawned with a pipe as its console writes its
    // ordinary greeting into the pipe, and nothing reaches the serial port.
    let capture = Pipe::create().map_err(|_| "create capture pipe")?;
    let capture_read =
        Pipe::from_raw(duplicate(capture.raw(), RIGHT_READ).map_err(|_| "dup capture read")?);
    let capture_write = duplicate(capture.raw(), RIGHT_WRITE).map_err(|_| "dup capture write")?;
    close(capture.raw()).map_err(|_| "close capture")?;
    let not_a_console = Cell::create(0).map_err(|_| "create decoy cell")?;
    match spawn_captured(program::HELLO_B, not_a_console.raw(), 0) {
        Err(Error::BadHandle) => {}
        _ => return Err("capture into a cell"),
    }
    close(not_a_console.raw()).map_err(|_| "close decoy cell")?;
    match spawn_captured(program::HELLO_B, capture_read.raw(), 0) {
        Err(Error::Rights) => {}
        _ => return Err("capture into a read-only end"),
    }
    let both_ends = Pipe::create().map_err(|_| "create undivided pipe")?;
    match spawn_captured(program::HELLO_B, both_ends.raw(), 0) {
        Err(Error::Rights) => {}
        _ => return Err("capture into an undivided pipe"),
    }
    close(both_ends.raw()).map_err(|_| "close undivided pipe")?;
    let captured =
        spawn_captured(program::HELLO_B, capture_write, 0).map_err(|_| "spawn captured")?;
    close(capture_write).map_err(|_| "close capture write")?;
    let mut collected = [0u8; 64];
    let mut filled = 0;
    loop {
        let count = capture_read
            .read_once(&mut collected[filled..])
            .map_err(|_| "capture read")?;
        if count == 0 {
            break;
        }
        filled += count;
    }
    if &collected[..filled] != b"user-B: hello from ELF userspace\n" {
        return Err("captured bytes");
    }
    expect_exit(captured, 0, "captured outcome")?;
    close(capture_read.raw()).map_err(|_| "close capture read")?;
    let _ = console.write_str("init: captured child output through a pipe\n");

    // Time: a child sleeps on the kernel clock while init waits with a
    // timeout too short to see it exit, then without one. A wait on a cell
    // nobody moves ends by timeout. Both leave nothing runnable meanwhile,
    // so the kernel has to idle until the timer wakes someone.
    let started = time();
    let sleeper = spawn_with(program::SLEEPER, 0, 40).map_err(|_| "spawn sleeper")?;
    match wait_timeout(Some(sleeper), 5) {
        Err(Error::Timeout) => {}
        _ => return Err("wait timeout"),
    }
    expect_exit(sleeper, 0, "sleeper outcome")?;
    if time() < started + 40 {
        return Err("sleep too short");
    }
    let still = Cell::create(0).map_err(|_| "create still cell")?;
    let before = time();
    match still.wait_change_timeout(0, 10) {
        Err(Error::Timeout) => {}
        _ => return Err("cell wait timeout"),
    }
    if time() < before + 10 {
        return Err("cell wait timeout too short");
    }
    close(still.raw()).map_err(|_| "close still cell")?;
    let _ = console.write_str("init: timed waits verified\n");

    // The ABI generation: a constant, the same on every call, equal to the
    // value this program was built against (the platform runtime refuses to
    // start on any other).
    let generation = abi_version().map_err(|_| "abi version")?;
    if generation != absd_abi::KERNEL_ABI || abi_version() != Ok(generation) {
        return Err("abi version mismatch");
    }
    let mut line = LineBuffer::new();
    let _ = writeln!(line, "ABI VERSION OK n={generation}");
    let _ = console.write_all(line.as_bytes());

    // The wall clock: the CMOS RTC, whole seconds. It must read, must not
    // run backwards, and must advance across a sleep of more than a second
    // (PIT ticks count delivered interrupts, so they never run ahead of
    // real time). The host checks the value against its own clock.
    let first = wall_clock().map_err(|_| "wall clock read")?;
    sleep(1_100);
    let second = wall_clock().map_err(|_| "wall clock second read")?;
    if second <= first {
        return Err("wall clock did not advance");
    }
    let mut line = LineBuffer::new();
    let _ = writeln!(
        line,
        "WALL CLOCK OK seconds={first} advanced={}",
        second - first
    );
    let _ = console.write_all(line.as_bytes());

    // Frame counts: one consistent allocator state per call. Mapping pages
    // moves exactly that many frames (plus any page tables) from free to
    // allocated and unmapping returns them; the tracked total never
    // changes after boot; a bad record address is refused.
    let before = frame_stats().map_err(|_| "frame stats")?;
    let total = before.free_frames + before.allocated_frames;
    if before.frame_bytes != 4096
        || before.allocation_limit != absd_abi::syscall::FRAME_LIMIT_NONE
        || before.free_frames == 0
    {
        return Err("frame stats record");
    }
    let pages = absd_abi::syscall::MAX_MAP_PAGES;
    let mapped = map(pages).map_err(|_| "frame stats map")?;
    let during = frame_stats().map_err(|_| "frame stats during")?;
    unmap(mapped, pages).map_err(|_| "frame stats unmap")?;
    let after = frame_stats().map_err(|_| "frame stats after")?;
    if during.free_frames + during.allocated_frames != total
        || after.free_frames + after.allocated_frames != total
        || during.allocated_frames < before.allocated_frames + pages
        || after.allocated_frames + pages > during.allocated_frames
    {
        return Err("frame stats accounting");
    }
    if Error::from_code(frame_stats_raw(0)) != Error::Fault {
        return Err("frame stats bad address");
    }
    let mut line = LineBuffer::new();
    let _ = writeln!(
        line,
        "FRAME STATS OK tracked={total} free={} allocated={} limit=none mapped={}",
        before.free_frames,
        before.allocated_frames,
        during.allocated_frames - before.allocated_frames
    );
    let _ = console.write_all(line.as_bytes());

    // Process metadata: about ourselves, about a live child, and about a
    // finished child whose outcome has not been collected yet.
    let me = info(None).map_err(|_| "info self")?;
    if me.pid != 1 || me.parent != 0 || me.program != program::INIT || me.state != INFO_STATE_LIVE {
        return Err("info self record");
    }
    let napper = spawn_with(program::SLEEPER, 0, 5).map_err(|_| "spawn napper")?;
    let child = info(Some(napper)).map_err(|_| "info child")?;
    if child.pid <= 1
        || child.parent != 1
        || child.program != program::SLEEPER
        || (child.state != INFO_STATE_LIVE && child.state != INFO_STATE_WAITING)
    {
        return Err("info child record");
    }
    // Elapsed ticks do not prove the child's continuation has run to exit.
    // Observe the unreaped terminal record under the existing bounded
    // supervision deadline; wait below still checks its exact outcome.
    let deadline = time().saturating_add(SUPERVISOR_WAIT_TICKS);
    loop {
        let record = info(Some(napper)).map_err(|_| "info finished child")?;
        match record.state {
            INFO_STATE_TERMINAL => break,
            INFO_STATE_LIVE | INFO_STATE_WAITING if time() < deadline => yield_now(),
            _ => return Err("info terminal state"),
        }
    }
    expect_exit(napper, 0, "napper outcome")?;
    match info(Some(napper)) {
        Err(Error::BadHandle) => {}
        _ => return Err("info after reap"),
    }

    verify_process_rights(console)?;

    // Cancellation: a child blocked forever on a cell nobody moves is
    // ended by kill; everything it held comes back and wait says Killed.
    let frozen = Cell::create(0).map_err(|_| "create frozen cell")?;
    let stuck = spawn_with(program::WATCHER, frozen.raw(), 0).map_err(|_| "spawn stuck watcher")?;
    expect_waiting(stuck, "stuck watcher not blocked")?;
    kill(stuck).map_err(|_| "kill")?;
    kill(stuck).map_err(|_| "kill again")?;
    match wait(Some(stuck)) {
        Ok(Outcome::Killed) => {}
        _ => return Err("killed outcome"),
    }
    match kill(stuck) {
        Err(Error::BadHandle) => {}
        _ => return Err("kill after reap"),
    }
    close(frozen.raw()).map_err(|_| "close frozen cell")?;
    let _ = console.write_str("init: cancellation verified\n");

    // Bounded transfers: with both ends held here, a read of the empty pipe
    // and a write into the full pipe each end by timeout instead of
    // waiting for a peer that never comes.
    let idle_pipe = Pipe::create().map_err(|_| "create idle pipe")?;
    let before = time();
    match idle_pipe.read_timeout(&mut [0u8; 8], 5) {
        Err(Error::Timeout) => {}
        _ => return Err("pipe read timeout"),
    }
    if time() < before + 5 {
        return Err("pipe read timeout too short");
    }
    let filler = [b'x'; 256];
    loop {
        match idle_pipe.write_timeout(&filler, 5) {
            Ok(_) => {}
            Err(Error::Timeout) => break,
            Err(_) => return Err("pipe fill"),
        }
    }
    close(idle_pipe.raw()).map_err(|_| "close idle pipe")?;
    let _ = console.write_str("init: bounded transfers verified\n");

    // Two concurrent SSE users must each keep their own register state.
    let fpu_a = spawn(program::FPU).map_err(|_| "spawn fpu")?;
    let fpu_b = spawn(program::FPU).map_err(|_| "spawn fpu")?;
    expect_exit(fpu_a, 0, "fpu outcome")?;
    expect_exit(fpu_b, 0, "fpu outcome")?;
    // Reaping closed the handle: it cannot be waited on or closed again.
    match wait(Some(fpu_b)) {
        Err(Error::BadHandle) => {}
        _ => return Err("stale child handle"),
    }
    match close(fpu_b.raw()) {
        Err(Error::BadHandle) => {}
        _ => return Err("close stale handle"),
    }
    // A closed process handle no longer waits, but wait-any still reaps.
    let closed = spawn(program::EXIT7).map_err(|_| "spawn closed")?;
    close(closed.raw()).map_err(|_| "close child handle")?;
    match wait(Some(closed)) {
        Err(Error::BadHandle) => {}
        _ => return Err("wait on closed handle"),
    }
    match wait_any() {
        Ok(result) if result.outcome == Outcome::Exited(7) => {}
        _ => return Err("wait-any after close"),
    }
    let _ = console.write_str("init: demonstration outcomes verified\n");

    verify_init_reaper(console)?;
    verify_supervision(console)?;
    verify_service_recovery(console)?;
    verify_client_service(console, reserve)?;

    // Phase 2: a worker applies a request and faults before reply. Its retained
    // cell stays inspectable while all process slots refuse the higher-
    // generation reconciler, which succeeds once one filler is reaped.
    let pressured = Cell::create(0).map_err(|_| "create pressured recovery cell")?;
    const PRESSURED_REQUEST: u64 = 0xd4;
    let (uncertain, uncertain_pid) = spawn_recovery_live(
        pressured,
        6,
        PRESSURED_REQUEST,
        program::RECOVERY_MODE_APPLY_THEN_FAULT,
    )?;
    report_recovery_instance(console, 6, uncertain_pid, PRESSURED_REQUEST);
    expect_recovery_fault(uncertain, "pressured predecessor outcome")?;
    if pressured.read() != Ok((1, PRESSURED_REQUEST)) {
        return Err("pressured predecessor state");
    }
    let recovery_fill_count = SPAWN_CAPACITY - reserve;
    let mut fillers = [Child::from_raw(0); SPAWN_CAPACITY];
    for filler in &mut fillers[..recovery_fill_count] {
        *filler = spawn(program::EXIT7).map_err(|_| "spawn to capacity")?;
    }
    require_process_count(PROCESS_TABLE_CAPACITY, "recovery full census")?;
    match spawn_recovery(
        pressured,
        7,
        PRESSURED_REQUEST,
        program::RECOVERY_MODE_RECONCILE,
    ) {
        Err(Error::Again) => {}
        Err(_) => return Err("wrong pressured supervisor error"),
        Ok(_) => return Err("pressured supervisor unexpectedly spawned"),
    }
    if pressured.read() != Ok((1, PRESSURED_REQUEST)) {
        return Err("pressured refusal changed recovery cell");
    }
    let _ = console.write_str("RECOVERY REPLACEMENT REFUSED\n");

    let released_pid = info(Some(fillers[0]))
        .map_err(|_| "inspect pressured filler")?
        .pid;
    expect_exit(fillers[0], 7, "reap pressured filler")?;
    require_process_count(PROCESS_TABLE_CAPACITY - 1, "recovery one-slot census")?;
    let replacement = match spawn_recovery(
        pressured,
        7,
        PRESSURED_REQUEST,
        program::RECOVERY_MODE_RECONCILE,
    ) {
        Ok(child) => child,
        Err(_) => return Err("pressured supervisor replacement spawn"),
    };
    require_process_count(PROCESS_TABLE_CAPACITY, "recovery replacement census")?;
    let replacement_info = info(Some(replacement)).map_err(|_| "inspect pressured replacement")?;
    let supervisor_pid = info(None).map_err(|_| "inspect pressured supervisor")?.pid;
    if replacement_info.pid == released_pid
        || replacement_info.parent != supervisor_pid
        || replacement_info.program != program::RECOVERY_WORKER
        || (replacement_info.state != INFO_STATE_LIVE
            && replacement_info.state != INFO_STATE_WAITING
            && replacement_info.state != INFO_STATE_TERMINAL)
    {
        return Err("pressured replacement identity");
    }
    report_recovery_instance(console, 7, replacement_info.pid, PRESSURED_REQUEST);
    if replacement_info.pid == uncertain_pid {
        return Err("pressured recovery reused predecessor pid");
    }
    expect_recovery_exit(replacement, "pressured recovery outcome")?;
    require_process_count(
        PROCESS_TABLE_CAPACITY - 1,
        "recovery replacement exit census",
    )?;
    if pressured.read() != Ok((1, PRESSURED_REQUEST)) {
        return Err("pressured replacement transition");
    }
    close(pressured.raw()).map_err(|_| "close pressured recovery cell")?;
    let _ = console.write_str("RECOVERY RESOURCE REFUSAL OK\n");
    let _ = console.write_str("SUPERVISOR RESOURCE REFUSAL OK\n");
    let _ = console.write_str("SERVICE RECOVERY OK\n");

    for _ in 1..recovery_fill_count {
        match wait_any() {
            Ok(result) if result.outcome == Outcome::Exited(7) => {}
            _ => return Err("wait-any outcome"),
        }
    }
    require_process_count(1 + reserve, "recovery drained census")?;
    match wait_any() {
        Err(Error::NoChild) => {}
        _ => return Err("wait with no children"),
    }
    // Teardown must make a process slot immediately reusable.
    let reused = spawn(program::EXIT7).map_err(|_| "spawn after process capacity")?;
    expect_exit(reused, 7, "process capacity reuse outcome")?;
    let _ = console.write_str("init: spawn capacity bounded and reaped\n");
    let _ = console.write_str("PROCESS CAPACITY OK\n");

    verify_handle_capacity(console)?;
    verify_object_capacity(console)?;

    // Phase 3: sequential spawn/exit/reap cycles, every fourth one a fault.
    for cycle in 0..STRESS_CYCLES {
        if cycle % 4 == 0 {
            let pid = spawn(program::FAULT).map_err(|_| "stress spawn fault")?;
            expect_fault(pid, "stress fault outcome")?;
        } else {
            let pid = spawn(program::EXIT7).map_err(|_| "stress spawn exit7")?;
            expect_exit(pid, 7, "stress exit outcome")?;
        }
    }
    let _ = console.write_str("init: lifecycle stress complete\n");
    Ok(())
}

fn verify_multi_handle_spawn(console: Console) -> Result<(), &'static str> {
    let cell = Cell::create(41).map_err(|_| "create multi cell")?;
    let readonly = duplicate(cell.raw(), RIGHT_READ).map_err(|_| "duplicate multi read-only")?;
    let good = [
        SpawnHandleCopy::new(cell.raw(), RIGHT_READ),
        SpawnHandleCopy::new(cell.raw(), RIGHT_WRITE),
        SpawnHandleCopy::console(console.raw(), RIGHT_WRITE),
    ];

    // The kernel validates the complete user range before looking at any
    // source handle, and refuses counts outside the fixed ABI bound.
    match spawn_many_copy_raw(program::MULTI_HANDLE, USER_ADDRESS_LIMIT, 1) {
        Err(Error::Fault) => {}
        _ => return Err("multi invalid pointer"),
    }
    match spawn_many_copy_raw(
        program::MULTI_HANDLE,
        good.as_ptr() as u64,
        MAX_SPAWN_HANDLES as u64 + 1,
    ) {
        Err(Error::Invalid) => {}
        _ => return Err("multi oversized count"),
    }
    match spawn_many_copy(
        program::MULTI_HANDLE,
        &[SpawnHandleCopy::new(u64::MAX, RIGHT_READ)],
    ) {
        Err(Error::BadHandle) => {}
        _ => return Err("multi invalid source"),
    }
    match spawn_many_copy(
        program::MULTI_HANDLE,
        &[SpawnHandleCopy::new(readonly, RIGHT_READ | RIGHT_WRITE)],
    ) {
        Err(Error::Rights) => {}
        _ => return Err("multi rights escalation"),
    }

    // Duplicate source entries are accepted and arrive as distinct ordered
    // handles. A console replacement coexists with both ordinary copies.
    let first = spawn_many_copy(program::MULTI_HANDLE, &good).map_err(|_| "spawn multi first")?;
    let first_pid = info(Some(first)).map_err(|_| "info multi first")?.pid;
    expect_exit(first, 0, "multi first outcome")?;
    if cell.read() != Ok((1, 42)) {
        return Err("multi first transition");
    }

    // Sixty-four ordinary destinations plus the child's default console
    // exceed its 64-slot table. Insertion gets most of the way through,
    // then must roll back every child handle, object reference, frame, slot,
    // and PID before returning this failure.
    let exhaust = [SpawnHandleCopy::new(cell.raw(), RIGHT_READ); MAX_SPAWN_HANDLES];
    match spawn_many_copy(program::MULTI_HANDLE, &exhaust) {
        Err(Error::TooManyHandles) => {}
        _ => return Err("multi destination capacity"),
    }
    let second =
        spawn_many_copy(program::MULTI_HANDLE, &good).map_err(|_| "spawn multi after rollback")?;
    if info(Some(second)).map_err(|_| "info multi second")?.pid != first_pid + 1 {
        return Err("multi rollback consumed pid");
    }
    expect_exit(second, 0, "multi second outcome")?;
    if cell.read() != Ok((2, 43)) {
        return Err("multi second transition");
    }
    // COPY semantics: all parent sources remain usable and explicitly close.
    if Cell::from_raw(readonly).read() != Ok((2, 43)) {
        return Err("multi parent source lost");
    }
    let console_probe = [SpawnHandleCopy::console(console.raw(), RIGHT_WRITE)];
    let console_parent = spawn_many_copy(program::MULTI_HANDLE, &console_probe)
        .map_err(|_| "spawn narrowed console parent")?;
    expect_exit(console_parent, 0, "narrowed console parent outcome")?;
    let _ = console.write_str("CHILD CONSOLE RIGHTS OK\n");
    close(readonly).map_err(|_| "close multi read-only")?;
    close(cell.raw()).map_err(|_| "close multi cell")?;
    let _ = console.write_str("MULTI HANDLE SPAWN OK\n");
    Ok(())
}

fn verify_pipe_cell_composition(console: Console) -> Result<(), &'static str> {
    let pipe = Pipe::create().map_err(|_| "create composed pipe")?;
    let reader = Pipe::from_raw(
        duplicate(pipe.raw(), RIGHT_READ).map_err(|_| "duplicate composed read end")?,
    );
    let writer = duplicate(pipe.raw(), RIGHT_WRITE).map_err(|_| "duplicate composed write end")?;
    close(pipe.raw()).map_err(|_| "close composed pipe")?;
    let cell = Cell::create(100).map_err(|_| "create composed cell")?;

    // The child gets exactly a write-only view of the shared cell and a
    // write-only pipe endpoint as its console. Neither source is moved out
    // of the parent; both are closed explicitly below after observation.
    let copies = [
        SpawnHandleCopy::new(cell.raw(), RIGHT_WRITE),
        SpawnHandleCopy::console(writer, RIGHT_WRITE),
    ];
    let child = spawn_many_copy(program::MULTI_HANDLE, &copies)
        .map_err(|_| "spawn pipe-cell composition")?;
    close(writer).map_err(|_| "close parent composed writer")?;

    // Drain to EOF before waiting. The child's short deterministic record
    // cannot fill the pipe, and EOF proves its last write endpoint closed.
    let mut captured = [0u8; 64];
    let mut length = 0;
    loop {
        let count = reader
            .read_once(&mut captured[length..])
            .map_err(|_| "read composed output")?;
        if count == 0 {
            break;
        }
        length += count;
        if length == captured.len() {
            return Err("composed output too long");
        }
    }
    if &captured[..length] != b"pipe-cell: version 1 value 101\n" {
        return Err("composed output content");
    }
    if reader.read_once(&mut [0u8; 1]) != Ok(0) {
        return Err("composed eof not stable");
    }
    expect_exit(child, 0, "pipe-cell child outcome")?;
    if cell.read() != Ok((1, 101)) {
        return Err("composed cell transition");
    }
    close(reader.raw()).map_err(|_| "close composed reader")?;
    close(cell.raw()).map_err(|_| "close composed cell")?;
    let _ = console.write_str("HANDLE TRANSFER OK\n");
    let _ = console.write_str("PIPE CELL COMPOSE OK\n");
    Ok(())
}

/// `pipe_info` counts every handle's read and write rights, across
/// processes, reports the fill level, never blocks, and refuses anything
/// that is not a live pipe handle.
fn verify_pipe_info(console: Console) -> Result<(), &'static str> {
    let both = Pipe::create().map_err(|_| "pipe info create")?;
    let reader = Pipe::from_raw(duplicate(both.raw(), RIGHT_READ).map_err(|_| "pipe info reader")?);
    let writer =
        Pipe::from_raw(duplicate(both.raw(), RIGHT_WRITE).map_err(|_| "pipe info writer")?);
    let expect = |pipe: Pipe, available, readers, writers, step| {
        let info = pipe.info().map_err(|_| step)?;
        if info.available != available
            || info.space != 1024 - available
            || info.readers != readers
            || info.writers != writers
        {
            return Err(step);
        }
        Ok(())
    };
    expect(both, 0, 2, 2, "pipe info fresh")?;
    close(both.raw()).map_err(|_| "pipe info split")?;
    expect(reader, 0, 1, 1, "pipe info split counts")?;
    writer.write_all(b"12345").map_err(|_| "pipe info write")?;
    expect(writer, 5, 1, 1, "pipe info fill")?;
    // A handle without rights counts as neither reader nor writer but may
    // still ask.
    let bare = Pipe::from_raw(duplicate(writer.raw(), 0).map_err(|_| "pipe info bare")?);
    expect(bare, 5, 1, 1, "pipe info bare handle")?;
    // A copy held by a child counts until the child is reaped.
    let child =
        spawn_with(program::SLEEPER, writer.raw(), 1_000_000).map_err(|_| "pipe info child")?;
    expect(reader, 5, 1, 2, "pipe info child writer")?;
    kill(child).map_err(|_| "pipe info child kill")?;
    let _ = wait(Some(child)).map_err(|_| "pipe info child wait")?;
    expect(reader, 5, 1, 1, "pipe info child reaped")?;
    close(writer.raw()).map_err(|_| "pipe info close writer")?;
    expect(bare, 5, 1, 0, "pipe info no writer")?;
    let mut drained = [0u8; 8];
    if reader.read_once(&mut drained) != Ok(5) || reader.read_once(&mut drained) != Ok(0) {
        return Err("pipe info end of file");
    }
    let cell = Cell::create(1).map_err(|_| "pipe info cell")?;
    if pipe_info(cell.raw()) != Err(Error::BadHandle)
        || pipe_info(0x7fff) != Err(Error::BadHandle)
        || pipe_info_raw(reader.raw(), 0) != -14
        || pipe_info_raw(reader.raw(), 0xffff_8000_0000_0000) != -14
    {
        return Err("pipe info refusals");
    }
    close(cell.raw()).map_err(|_| "pipe info cell close")?;
    close(bare.raw()).map_err(|_| "pipe info bare close")?;
    close(reader.raw()).map_err(|_| "pipe info reader close")?;
    if pipe_info(reader.raw()) != Err(Error::BadHandle) {
        return Err("pipe info stale handle");
    }
    let _ = console.write_str("PIPE INFO OK\n");
    Ok(())
}

fn verify_input_stream(console: Console) -> Result<(), &'static str> {
    let input = Pipe::create().map_err(|_| "create input stream")?;
    let input_reader = duplicate(input.raw(), RIGHT_READ).map_err(|_| "duplicate input reader")?;
    let input_writer =
        Pipe::from_raw(duplicate(input.raw(), RIGHT_WRITE).map_err(|_| "duplicate input writer")?);
    close(input.raw()).map_err(|_| "close combined input stream")?;

    let output = Pipe::create().map_err(|_| "create stream output")?;
    let output_reader =
        Pipe::from_raw(duplicate(output.raw(), RIGHT_READ).map_err(|_| "duplicate output reader")?);
    let output_writer =
        duplicate(output.raw(), RIGHT_WRITE).map_err(|_| "duplicate output writer")?;
    close(output.raw()).map_err(|_| "close combined stream output")?;

    let copies = [
        SpawnHandleCopy::new(input_reader, RIGHT_READ),
        SpawnHandleCopy::console(output_writer, RIGHT_WRITE),
    ];
    let child =
        spawn_many_copy(program::INPUT_STREAM, &copies).map_err(|_| "spawn input stream probe")?;
    close(input_reader).map_err(|_| "close parent input reader")?;
    close(output_writer).map_err(|_| "close parent output writer")?;

    // More than one pipe capacity is generated incrementally. A full pipe
    // blocks this producer until the concurrently running child drains it.
    let mut sent = 0usize;
    while sent < program::INPUT_STREAM_BYTES {
        let mut chunk = [0u8; 211];
        let count = (program::INPUT_STREAM_BYTES - sent).min(chunk.len());
        for (offset, byte) in chunk[..count].iter_mut().enumerate() {
            *byte = program::input_stream_byte(sent + offset);
        }
        input_writer
            .write_all(&chunk[..count])
            .map_err(|_| "write input stream")?;
        sent += count;
    }
    close(input_writer.raw()).map_err(|_| "close input writer")?;

    let mut report = [0u8; 64];
    let mut length = 0usize;
    loop {
        if length == report.len() {
            return Err("input stream report too long");
        }
        let count = output_reader
            .read_once(&mut report[length..])
            .map_err(|_| "read input stream report")?;
        if count == 0 {
            break;
        }
        length += count;
    }
    if &report[..length] != b"stream-input: bytes=1245 digest=faef2b56\n" {
        return Err("input stream report content");
    }
    expect_exit(child, 0, "input stream outcome")?;
    close(output_reader.raw()).map_err(|_| "close output reader")?;
    let _ = console.write_str("INPUT STREAM OK\n");
    Ok(())
}

/// Repeats cross-process object ownership transitions enough times to expose
/// stale-generation and reference-count errors. Every cycle closes parent
/// sources before the child is collected, and every remaining local handle
/// is explicitly released.
fn verify_handle_lifetime_stress(console: Console) -> Result<(), &'static str> {
    for cycle in 0..HANDLE_LIFETIME_CYCLES as u64 {
        // A multi-entry child retains two independently narrowed copies after
        // the parent closes their common source. Other parent copies remain
        // valid after child exit and reap.
        let cell = Cell::create(cycle).map_err(|_| "lifetime create cell")?;
        let readonly = duplicate(cell.raw(), RIGHT_READ).map_err(|_| "lifetime narrow cell")?;
        let observer = duplicate(cell.raw(), RIGHT_READ | RIGHT_WRITE)
            .map_err(|_| "lifetime duplicate observer")?;
        if duplicate(readonly, RIGHT_READ | RIGHT_WRITE) != Err(Error::Rights) {
            return Err("lifetime rights escalation");
        }
        let readonly_copy =
            duplicate(readonly, RIGHT_READ).map_err(|_| "lifetime duplicate narrowed")?;
        let copies = [
            SpawnHandleCopy::new(cell.raw(), RIGHT_READ),
            SpawnHandleCopy::new(cell.raw(), RIGHT_WRITE),
            SpawnHandleCopy::console(console.raw(), RIGHT_WRITE),
        ];
        let child =
            spawn_many_copy(program::MULTI_HANDLE, &copies).map_err(|_| "lifetime spawn multi")?;
        close(cell.raw()).map_err(|_| "lifetime close parent source")?;
        expect_exit(child, 0, "lifetime multi outcome")?;
        if Cell::from_raw(readonly).read() != Ok((1, cycle + 1))
            || Cell::from_raw(observer).read() != Ok((1, cycle + 1))
        {
            return Err("lifetime cell separation");
        }
        close(readonly_copy).map_err(|_| "lifetime close narrowed copy")?;
        if close(readonly_copy) != Err(Error::BadHandle) {
            return Err("lifetime stale close");
        }
        close(readonly).map_err(|_| "lifetime close narrowed")?;
        close(observer).map_err(|_| "lifetime close observer")?;

        // The watcher blocks with the only remaining cell reference. Closing
        // the parent's source must not invalidate it; kill releases that last
        // reference, and reap reports the requested terminal outcome.
        let frozen = Cell::create(0).map_err(|_| "lifetime create frozen")?;
        let blocked =
            spawn_with(program::WATCHER, frozen.raw(), 0).map_err(|_| "lifetime spawn blocked")?;
        close(frozen.raw()).map_err(|_| "lifetime close frozen source")?;
        expect_waiting(blocked, "lifetime watcher not blocked")?;
        kill(blocked).map_err(|_| "lifetime kill blocked")?;
        match wait(Some(blocked)) {
            Ok(Outcome::Killed) => {}
            _ => return Err("lifetime killed outcome"),
        }

        // This child never touches its inherited pipe handle. While it is
        // live, its writer keeps an empty read blocked. Process termination
        // releases the writer before reap, so EOF is observable while the
        // terminal process record still exists.
        let held = Pipe::create().map_err(|_| "lifetime create held pipe")?;
        let held_reader =
            Pipe::from_raw(duplicate(held.raw(), RIGHT_READ).map_err(|_| "lifetime held read")?);
        let held_writer = duplicate(held.raw(), RIGHT_WRITE).map_err(|_| "lifetime held write")?;
        close(held.raw()).map_err(|_| "lifetime close held pipe")?;
        let holder =
            spawn_with(program::SLEEPER, held_writer, 20).map_err(|_| "lifetime spawn holder")?;
        close(held_writer).map_err(|_| "lifetime close held writer")?;
        match held_reader.read_timeout(&mut [0u8; 1], 1) {
            Err(Error::Timeout) => {}
            _ => return Err("lifetime writer not retained"),
        }
        // Wait for teardown itself instead of assuming a delay is long
        // enough: EOF is delivered only after exit drops the child's last
        // writer, while its terminal process record is still unreaped.
        if held_reader.read_once(&mut [0u8; 1]) != Ok(0) {
            return Err("lifetime eof before reap");
        }
        if info(Some(holder))
            .map_err(|_| "lifetime info terminal holder")?
            .state
            != INFO_STATE_TERMINAL
        {
            return Err("lifetime holder not terminal");
        }
        expect_exit(holder, 0, "lifetime holder outcome")?;
        match info(Some(holder)) {
            Err(Error::BadHandle) => {}
            _ => return Err("lifetime holder handle after reap"),
        }
        close(held_reader.raw()).map_err(|_| "lifetime close held reader")?;

        // Captured output uses a child-owned console writer after its parent
        // source is closed. EOF proves the endpoint vanished on exit.
        let captured = Pipe::create().map_err(|_| "lifetime create capture")?;
        let capture_reader = Pipe::from_raw(
            duplicate(captured.raw(), RIGHT_READ).map_err(|_| "lifetime capture read")?,
        );
        let capture_writer =
            duplicate(captured.raw(), RIGHT_WRITE).map_err(|_| "lifetime capture write")?;
        close(captured.raw()).map_err(|_| "lifetime close capture")?;
        let speaker = spawn_captured(program::HELLO_B, capture_writer, 0)
            .map_err(|_| "lifetime spawn captured")?;
        close(capture_writer).map_err(|_| "lifetime close capture writer")?;
        let mut bytes = [0u8; 40];
        let mut length = 0;
        loop {
            let count = capture_reader
                .read_once(&mut bytes[length..])
                .map_err(|_| "lifetime read capture")?;
            if count == 0 {
                break;
            }
            length += count;
            if length == bytes.len() {
                return Err("lifetime capture too long");
            }
        }
        if &bytes[..length] != b"user-B: hello from ELF userspace\n" {
            return Err("lifetime capture content");
        }
        if capture_reader.read_once(&mut [0u8; 1]) != Ok(0) {
            return Err("lifetime capture eof unstable");
        }
        expect_exit(speaker, 0, "lifetime captured outcome")?;
        close(capture_reader.raw()).map_err(|_| "lifetime close capture reader")?;

        // Dropping the final reader turns a surviving write-only endpoint
        // into an immediate broken pipe rather than a permanent block.
        let lonely = Pipe::create().map_err(|_| "lifetime create lonely")?;
        let lonely_writer =
            Pipe::from_raw(duplicate(lonely.raw(), RIGHT_WRITE).map_err(|_| "lifetime lonely")?);
        close(lonely.raw()).map_err(|_| "lifetime drop lonely reader")?;
        if lonely_writer.write_once(b"x") != Err(Error::BrokenPipe) {
            return Err("lifetime broken pipe");
        }
        close(lonely_writer.raw()).map_err(|_| "lifetime close lonely writer")?;
    }
    let _ = console.write_str("HANDLE LIFETIME STRESS OK\n");
    Ok(())
}

/// Process-control authority may be narrowed locally, but process handles
/// never cross a spawn boundary because parentage and reaping stay local.
fn verify_process_rights(console: Console) -> Result<(), &'static str> {
    // Reaping a process record consumes every handle in the parent's table,
    // not only the handle used to wait.
    let reaped = spawn_with(program::SLEEPER, 0, 100).map_err(|_| "process reap spawn")?;
    let reaped_wait = Child::from_raw(
        duplicate(reaped.raw(), RIGHT_WAIT).map_err(|_| "process reap duplicate wait")?,
    );
    let reaped_kill = Child::from_raw(
        duplicate(reaped.raw(), RIGHT_KILL).map_err(|_| "process reap duplicate kill")?,
    );
    kill(reaped_kill).map_err(|_| "process reap kill")?;
    match wait_timeout(Some(reaped_wait), 500) {
        Ok(Outcome::Killed) => {}
        _ => return Err("process reap outcome"),
    }
    if info(Some(reaped)) != Err(Error::BadHandle)
        || wait_timeout(Some(reaped_wait), 1) != Err(Error::BadHandle)
        || kill(reaped_kill) != Err(Error::BadHandle)
    {
        return Err("process reap left a live handle");
    }
    let _ = console.write_str("PROCESS HANDLE REAP OK\n");

    let child = spawn_with(program::SLEEPER, 0, 100).map_err(|_| "process rights spawn")?;
    let child_pid = info(Some(child)).map_err(|_| "process rights info")?.pid;
    let wait_only = Child::from_raw(
        duplicate(child.raw(), RIGHT_WAIT).map_err(|_| "process rights duplicate wait")?,
    );
    let kill_only = Child::from_raw(
        duplicate(child.raw(), RIGHT_KILL).map_err(|_| "process rights duplicate kill")?,
    );

    if kill(wait_only) != Err(Error::Rights) {
        return Err("wait-only process handle killed");
    }
    if info(Some(kill_only)) != Err(Error::Rights) {
        return Err("kill-only process handle inspected");
    }
    if wait_timeout(Some(kill_only), 1) != Err(Error::Rights) {
        return Err("kill-only process handle waited");
    }

    // Both legacy and descriptor-array transfer reject process objects before
    // claiming a child slot. The next successful spawn proves PID rollback.
    if spawn_with(program::EXIT7, child.raw(), 0) != Err(Error::BadHandle) {
        return Err("legacy process handle transfer");
    }
    let process_copy = [SpawnHandleCopy::new(child.raw(), RIGHT_WAIT)];
    if spawn_many_copy(program::MULTI_HANDLE, &process_copy) != Err(Error::BadHandle) {
        return Err("multi process handle transfer");
    }

    // Remove every wait-capable handle before termination. Targeted wait was
    // refused above, but parentage still lets this process reap the child:
    // wait-any must identify and reap the child without consulting a handle.
    close(child.raw()).map_err(|_| "close full process handle")?;
    close(wait_only.raw()).map_err(|_| "close wait-only process handle")?;
    kill(kill_only).map_err(|_| "kill-only process handle")?;
    match wait_any() {
        Ok(result) if result.pid == child_pid && result.outcome == Outcome::Killed => {}
        _ => return Err("wait-any parentage outcome"),
    }
    let _ = console.write_str("WAIT ANY PARENTAGE OK\n");
    let probe = spawn(program::EXIT7).map_err(|_| "process rights rollback probe")?;
    if info(Some(probe))
        .map_err(|_| "process rights probe info")?
        .pid
        != child_pid + 1
    {
        return Err("process transfer consumed pid");
    }
    expect_exit(probe, 7, "process rights probe outcome")?;
    let _ = console.write_str("PROCESS RIGHTS OK\n");
    Ok(())
}

/// PID 1 adopts both terminal and live grandchildren. The orphaner's own
/// handle is targeted first, leaving identified wait-any to collect exactly
/// the adopted child and prove its original outcome survived reparenting.
/// Adoption makes init the parent for reaping only: the numeric PID is not a
/// handle.
fn verify_init_reaper(console: Console) -> Result<(), &'static str> {
    let first_terminal = reap_terminal_orphan(true)?;
    let second_terminal = reap_terminal_orphan(false)?;
    if first_terminal == second_terminal {
        return Err("adopted terminal identity reused");
    }

    let live = spawn_with(program::ORPHANER, 0, 1).map_err(|_| "spawn live orphaner")?;
    let live_pid = info(Some(live)).map_err(|_| "inspect live orphaner")?.pid;
    expect_exit(live, 0, "live orphaner outcome")?;
    match wait_any_timeout(SUPERVISOR_WAIT_TICKS) {
        Ok(result) if result.pid == live_pid + 1 && result.outcome == Outcome::Exited(0) => {}
        _ => return Err("adopt live orphan outcome"),
    }
    verify_adoption_handle_pressure()?;
    let _ = console.write_str("WAIT ANY PID OK\n");
    let _ = console.write_str("ORPHAN ADOPTION OK\n");
    let _ = console.write_str("ADOPTION HANDLE PRESSURE OK\n");
    let _ = console.write_str("INIT REAPER OK\n");
    Ok(())
}

/// Fill PID 1's handle table before an orphan becomes adoptable. Reparenting
/// is a parent link recorded in the process table, so it must neither mint
/// authority nor consume a handle slot in the adopter.
fn verify_adoption_handle_pressure() -> Result<(), &'static str> {
    let control = Cell::create(0).map_err(|_| "adoption pressure control")?;
    let reader = duplicate(control.raw(), RIGHT_READ).map_err(|_| "adoption pressure reader")?;
    let orphaner =
        spawn_with(program::ORPHANER, reader, 2).map_err(|_| "adoption pressure spawn orphaner")?;
    close(reader).map_err(|_| "adoption pressure close reader")?;
    let orphaner_pid = info(Some(orphaner))
        .map_err(|_| "adoption pressure inspect orphaner")?
        .pid;
    yield_now();

    let mut held = [0u64; MAX_SPAWN_HANDLES];
    let mut count = 0;
    loop {
        match duplicate(control.raw(), RIGHT_READ) {
            Ok(handle) => {
                held[count] = handle;
                count += 1;
            }
            Err(Error::TooManyHandles) => break,
            Err(_) => return Err("adoption pressure fill handles"),
        }
        if count == held.len() {
            return Err("adoption pressure exceeded handle bound");
        }
    }
    // Console, the machine handle, control, and the orphaner's process
    // handle occupy four slots.
    if count != MAX_SPAWN_HANDLES - 4 || Cell::create(1) != Err(Error::TooManyHandles) {
        return Err("adoption pressure initial boundary");
    }

    if control.transition(0, 1) != Ok(1) {
        return Err("adoption pressure release orphaner");
    }
    let deadline = time().saturating_add(SUPERVISOR_WAIT_TICKS);
    loop {
        match info(Some(orphaner)) {
            Ok(record) if record.state == INFO_STATE_TERMINAL => break,
            Ok(_) if time() < deadline => yield_now(),
            Ok(_) => return Err("adoption pressure orphaner deadline"),
            Err(_) => return Err("adoption pressure inspect terminal orphaner"),
        }
    }
    // The adopted terminal child is now PID 1's cleanup responsibility, but
    // the table remains exactly full: adoption consumed no handle slot.
    if Cell::create(2) != Err(Error::TooManyHandles) {
        return Err("adoption consumed or freed handle slot");
    }

    close(held[0]).map_err(|_| "adoption pressure free explicit slot")?;
    let probe = Cell::create(3).map_err(|_| "adoption pressure reuse explicit slot")?;
    if probe.read() != Ok((0, 3)) {
        return Err("adoption pressure reuse probe");
    }
    close(probe.raw()).map_err(|_| "adoption pressure close probe")?;
    expect_exit(orphaner, 0, "adoption pressure orphaner outcome")?;
    match wait_any_timeout(SUPERVISOR_WAIT_TICKS) {
        Ok(result) if result.pid == orphaner_pid + 1 && result.outcome == Outcome::Exited(7) => {}
        _ => return Err("adoption pressure child outcome"),
    }

    for &handle in &held[1..count] {
        close(handle).map_err(|_| "adoption pressure drain handle")?;
    }
    close(control.raw()).map_err(|_| "adoption pressure close control")?;
    Ok(())
}

fn reap_terminal_orphan(check_authority: bool) -> Result<u64, &'static str> {
    let orphaner = spawn_with(program::ORPHANER, 0, 0).map_err(|_| "spawn terminal orphaner")?;
    let orphaner_pid = info(Some(orphaner))
        .map_err(|_| "inspect terminal orphaner")?
        .pid;
    expect_exit(orphaner, 0, "terminal orphaner outcome")?;
    let adopted_pid = orphaner_pid + 1;
    if check_authority {
        let guessed = Child::from_raw(adopted_pid);
        if info(Some(guessed)) != Err(Error::BadHandle) || kill(guessed) != Err(Error::BadHandle) {
            return Err("adoption minted process authority");
        }
    }
    match wait_any_timeout(SUPERVISOR_WAIT_TICKS) {
        Ok(result) if result.pid == adopted_pid && result.outcome == Outcome::Exited(7) => {
            Ok(result.pid)
        }
        _ => Err("adopt terminal orphan outcome"),
    }
}

/// Restarts are an ordinary userspace policy: each instance is a fresh
/// process receiving one fresh, rights-narrowed copy of an explicit cell.
fn verify_supervision(console: Console) -> Result<(), &'static str> {
    let recovery = Cell::create(0).map_err(|_| "supervisor create recovery cell")?;
    let recovery_handle = recovery.raw();

    let (first, first_pid) = spawn_supervised_live(recovery, 1)?;
    report_supervised_instance(console, 1, first_pid);
    expect_supervised_fault(first, "supervisor first outcome")?;
    if recovery.read() != Ok((1, 1)) {
        return Err("supervisor first transition");
    }
    let _ = console.write_str("SUPERVISOR OBSERVED FAULT\n");

    let (replacement, replacement_pid) = spawn_supervised_live(recovery, 2)?;
    report_supervised_instance(console, 2, replacement_pid);
    if replacement_pid == first_pid {
        return Err("supervisor replacement identity");
    }
    let _ = console.write_str("SUPERVISOR REPLACEMENT SPAWNED\n");
    expect_supervised_exit(replacement)?;
    if recovery.read() != Ok((2, 2)) {
        return Err("supervisor replacement transition");
    }
    let _ = console.write_str("SUPERVISOR RECONCILE OK\n");
    close(recovery.raw()).map_err(|_| "supervisor close recovery cell")?;

    // Orderly stop is an ordinary control-cell transition followed by a
    // bounded wait. The worker holds read/wait authority only.
    let graceful = Cell::create(0).map_err(|_| "supervisor create graceful cell")?;
    let graceful_worker =
        spawn_supervised_control(graceful, program::SUPERVISED_MODE_GRACEFUL_STOP, 3)?;
    let graceful_pid = info(Some(graceful_worker))
        .map_err(|_| "supervisor inspect graceful worker")?
        .pid;
    report_supervised_instance(console, 3, graceful_pid);
    // Reaching a fresh cell, duplicate, process slot, and process handle only
    // after the replacement survived and recovery state resolved establishes
    // the slack needed for the next required operation.
    let _ = console.write_str("SUPERVISOR CLOSURE OK\n");
    let _ = console.write_str("SUPERVISOR RESTART OK\n");
    yield_now();
    if graceful.transition(0, program::SUPERVISED_STOP_VALUE) != Ok(1) {
        return Err("supervisor request graceful stop");
    }
    expect_supervised_exit(graceful_worker)?;
    close(graceful.raw()).map_err(|_| "supervisor close graceful cell")?;
    let _ = console.write_str("SUPERVISOR GRACEFUL STOP OK\n");
    let _ = console.write_str("GRACEFUL STOP OK\n");

    // A non-progressing instance receives the same explicit stop request.
    // Only after its bounded wait expires does init use the child handle's
    // kill right, preserving Exited versus Killed as distinct outcomes.
    let stuck = Cell::create(0).map_err(|_| "supervisor create stuck cell")?;
    let stuck_worker = spawn_supervised_control(stuck, program::SUPERVISED_MODE_STUCK, 4)?;
    let stuck_pid = info(Some(stuck_worker))
        .map_err(|_| "supervisor inspect stuck worker")?
        .pid;
    report_supervised_instance(console, 4, stuck_pid);
    // This fixture's only block is its indefinite sleep after the mandatory
    // rights refusal. A scheduling yield alone cannot prove that prefix ran.
    expect_waiting(stuck_worker, "supervisor stuck setup waiting")?;
    let _ = absd_user::cprintln!(
        console,
        "SUPERVISOR STUCK READY pid={} state=waiting after-rights-check=1",
        stuck_pid
    );
    if stuck.transition(0, program::SUPERVISED_STOP_VALUE) != Ok(1) {
        return Err("supervisor request stuck stop");
    }
    match wait_timeout(Some(stuck_worker), 5) {
        Err(Error::Timeout) => {}
        _ => return Err("supervisor stuck deadline did not expire"),
    }
    kill(stuck_worker).map_err(|_| "supervisor kill stuck worker")?;
    match wait_timeout(Some(stuck_worker), SUPERVISOR_WAIT_TICKS) {
        Ok(Outcome::Killed) => {}
        _ => return Err("supervisor reap stuck worker"),
    }
    if info(Some(stuck_worker)) != Err(Error::BadHandle) {
        return Err("supervisor stuck handle remained live");
    }
    close(stuck.raw()).map_err(|_| "supervisor close stuck cell")?;
    let _ = console.write_str("SUPERVISOR STOP FALLBACK OK\n");
    let _ = console.write_str("SUPERVISOR TIMED WAIT OK\n");
    let _ = console.write_str("FORCED STOP OK\n");

    // Version two is the local escalation sentinel. Each fresh worker finds
    // both allowed transitions stale and faults. The fixed restart budget is
    // exhausted after exactly two instances; there is no third spawn site.
    const MAX_RESTARTS: usize = 2;
    let escalation = Cell::create(0).map_err(|_| "supervisor create escalation cell")?;
    if escalation.raw() == recovery_handle
        || escalation.transition(0, u64::MAX) != Ok(1)
        || escalation.transition(1, u64::MAX) != Ok(2)
    {
        return Err("supervisor escalation sentinel");
    }
    let mut attempts = 0;
    let mut previous_pid = 0;
    while attempts < MAX_RESTARTS {
        let generation = attempts as u64 + 1;
        let (worker, pid) = spawn_supervised_live(escalation, generation)?;
        report_supervised_instance(console, generation, pid);
        if pid == previous_pid {
            return Err("supervisor escalation identity");
        }
        previous_pid = pid;
        expect_supervised_fault(worker, "supervisor escalation outcome")?;
        attempts += 1;
    }
    if attempts != MAX_RESTARTS || escalation.read() != Ok((2, u64::MAX)) {
        return Err("supervisor escalation budget");
    }
    let escalation_handle = escalation.raw();
    close(escalation.raw()).map_err(|_| "supervisor close escalation cell")?;
    let _ = console.write_str("SUPERVISOR ESCALATION OK\n");

    // The next cell allocation succeeds immediately, carries a new opaque
    // handle value, and is independently readable: no worker reference or
    // terminal process record survived its wait.
    let probe =
        Cell::create(0x5355_5045_5256_4953).map_err(|_| "supervisor create reclaim probe")?;
    if probe.raw() == escalation_handle || probe.read() != Ok((0, 0x5355_5045_5256_4953)) {
        return Err("supervisor reclaim probe");
    }
    close(probe.raw()).map_err(|_| "supervisor close reclaim probe")?;
    let _ = console.write_str("SUPERVISOR RECLAIM OK\n");
    Ok(())
}

/// Bounded userspace request recovery over one explicitly shared cell per
/// case. A replacement is always a fresh process and is never called recovery
/// until its exact outcome and the authoritative cell state are reconciled.
fn verify_service_recovery(console: Console) -> Result<(), &'static str> {
    const REQUEST_A: u64 = 0xa1;
    const REQUEST_B: u64 = 0xb2;
    const REQUEST_C: u64 = 0xc3;
    let mut pids = [0u64; 6];

    // Case A: failure before mutation leaves the request unapplied. Exactly
    // one fresh, bounded retry performs the conditional update.
    let before = Cell::create(0).map_err(|_| "recovery create pre-request cell")?;
    let before_handle = before.raw();
    let (first, first_pid) =
        spawn_recovery_live(before, 1, REQUEST_A, program::RECOVERY_MODE_FAULT_BEFORE)?;
    pids[0] = first_pid;
    report_recovery_instance(console, 1, first_pid, REQUEST_A);
    expect_recovery_fault(first, "pre-request worker outcome")?;
    if before.raw() != before_handle || before.read() != Ok((0, 0)) {
        return Err("pre-request state changed");
    }
    let _ = console.write_str("RECOVERY NOT PERFORMED OK\n");
    sleep(1);
    let (retry, retry_pid) =
        spawn_recovery_live(before, 2, REQUEST_A, program::RECOVERY_MODE_NORMAL)?;
    pids[1] = retry_pid;
    report_recovery_instance(console, 2, retry_pid, REQUEST_A);
    if retry_pid == first_pid {
        return Err("recovery retry identity");
    }
    expect_recovery_exit(retry, "recovery retry outcome")?;
    if before.raw() != before_handle || before.read() != Ok((1, REQUEST_A)) {
        return Err("recovery retry state");
    }
    close(before.raw()).map_err(|_| "recovery close pre-request cell")?;
    let _ = console.write_str("REQUEST IDENTITY OK\n");
    let _ = console.write_str("CONDITIONAL SERVICE UPDATE OK\n");

    // Case B: the request was applied before the reply was lost. The fresh
    // process classifies applied(request), proves expected version zero is
    // stale, and exits without advancing the cell again.
    let applied = Cell::create(0).map_err(|_| "recovery create applied cell")?;
    let applied_handle = applied.raw();
    let (uncertain, uncertain_pid) = spawn_recovery_live(
        applied,
        3,
        REQUEST_B,
        program::RECOVERY_MODE_APPLY_THEN_FAULT,
    )?;
    pids[2] = uncertain_pid;
    report_recovery_instance(console, 3, uncertain_pid, REQUEST_B);
    expect_recovery_fault(uncertain, "applied-before-reply outcome")?;
    if applied.read() != Ok((1, REQUEST_B)) {
        return Err("applied-before-reply state");
    }
    sleep(1);
    let (reconcile, reconcile_pid) =
        spawn_recovery_live(applied, 4, REQUEST_B, program::RECOVERY_MODE_RECONCILE)?;
    pids[3] = reconcile_pid;
    report_recovery_instance(console, 4, reconcile_pid, REQUEST_B);
    if reconcile_pid == uncertain_pid {
        return Err("reconcile replacement identity");
    }
    let _ = console.write_str("RESTART BEFORE RECOVERY OK\n");
    expect_recovery_exit(reconcile, "reconcile outcome")?;
    if applied.raw() != applied_handle || applied.read() != Ok((1, REQUEST_B)) {
        return Err("reconcile double applied");
    }
    let _ = console.write_str("RECOVERY RECONCILE OK\n");

    // Generation is diagnostic startup data, not authority or a fencing
    // token. A deliberately older fresh instance must still classify the
    // already-applied request and leave the authoritative state unchanged.
    let (stale_generation, stale_pid) =
        spawn_recovery_live(applied, 2, REQUEST_B, program::RECOVERY_MODE_RECONCILE)?;
    pids[5] = stale_pid;
    report_recovery_instance(console, 2, stale_pid, REQUEST_B);
    if stale_pid == uncertain_pid || stale_pid == reconcile_pid {
        return Err("stale generation process identity");
    }
    expect_recovery_exit(stale_generation, "stale generation outcome")?;
    if applied.raw() != applied_handle || applied.read() != Ok((1, REQUEST_B)) {
        return Err("stale generation changed state");
    }
    close(applied.raw()).map_err(|_| "recovery close applied cell")?;
    let _ = console.write_str("NO DOUBLE APPLY OK\n");
    let _ = console.write_str("SERVICE STATE SURVIVES RESTART OK\n");

    // Case C: the ordinary request/reply path performs one transition and
    // reports a normal exit, without invoking any recovery policy.
    let normal = Cell::create(0).map_err(|_| "recovery create normal cell")?;
    let (worker, worker_pid) =
        spawn_recovery_live(normal, 5, REQUEST_C, program::RECOVERY_MODE_NORMAL)?;
    pids[4] = worker_pid;
    report_recovery_instance(console, 5, worker_pid, REQUEST_C);
    expect_recovery_exit(worker, "normal service outcome")?;
    if normal.read() != Ok((1, REQUEST_C)) {
        return Err("normal service state");
    }
    close(normal.raw()).map_err(|_| "recovery close normal cell")?;
    let _ = console.write_str("RECOVERY NORMAL COMPLETION OK\n");

    for left in 0..pids.len() {
        for right in left + 1..pids.len() {
            if pids[left] == pids[right] {
                return Err("service generation pid reused");
            }
        }
    }
    let _ = console.write_str("SERVICE GENERATION OK\n");
    Ok(())
}

/// One long-lived userspace client observes a stable three-cell service slot
/// while init explicitly replaces every worker. Generation is directory
/// metadata; conditional transitions on `state` decide whether a request was
/// applied, and init alone retains process handles.
fn verify_client_service(console: Console, reserve: usize) -> Result<(), &'static str> {
    let status = Cell::create(0).map_err(|_| "client service create status")?;
    let control = Cell::create(0).map_err(|_| "client service create control")?;
    let state = Cell::create(0).map_err(|_| "client service create state")?;
    let stable_handles = [status.raw(), control.raw(), state.raw()];
    let client =
        spawn_service_client(status, control, state).map_err(|_| "client service spawn client")?;
    let client_pid = info(Some(client))
        .map_err(|_| "client service inspect client")?
        .pid;
    require_process_count(2 + reserve, "client service baseline census")?;
    let mut status_version = 0;
    let mut worker_pids = [0u64; 9];

    // Generation 1 fails before mutation. Publishing UNAVAILABLE only after
    // exact fault classification tells the client that the same request is
    // still pending rather than inviting a blind concurrent retry.
    publish_client_service(
        status,
        control,
        &mut status_version,
        program::CLIENT_SERVICE_COMMAND_FAULT,
        1,
        0,
        1,
        program::CLIENT_SERVICE_REQUEST_A,
    )?;
    let first = spawn_service_worker(status, control, state)
        .map_err(|_| "client service spawn generation 1")?;
    worker_pids[0] = service_worker_pid(first, client_pid, &worker_pids[..0])?;
    publish_client_service(
        status,
        control,
        &mut status_version,
        program::CLIENT_SERVICE_ACTIVE_FAULT,
        1,
        worker_pids[0],
        1,
        program::CLIENT_SERVICE_REQUEST_A,
    )?;
    expect_client_service_fault(first, "client service generation 1 outcome")?;
    require_service_state(state, 0, 0)?;
    publish_client_service(
        status,
        control,
        &mut status_version,
        program::CLIENT_SERVICE_UNAVAILABLE,
        1,
        0,
        1,
        program::CLIENT_SERVICE_REQUEST_A,
    )?;
    require_service_state(state, 0, 0)?;
    let _ = console.write_str("CLIENT RETRY NOT PERFORMED OK\n");

    // Generation 2 performs the sole retry, then remains alive until the
    // client has observed completion and init explicitly publishes STOP.
    publish_client_service(
        status,
        control,
        &mut status_version,
        program::CLIENT_SERVICE_COMMAND_RETRY,
        2,
        0,
        2,
        program::CLIENT_SERVICE_REQUEST_A,
    )?;
    let retry = spawn_service_worker(status, control, state)
        .map_err(|_| "client service spawn generation 2")?;
    worker_pids[1] = service_worker_pid(retry, client_pid, &worker_pids[..1])?;
    publish_client_service(
        status,
        control,
        &mut status_version,
        program::CLIENT_SERVICE_ACTIVE_RETRY,
        2,
        worker_pids[1],
        2,
        program::CLIENT_SERVICE_REQUEST_A,
    )?;
    wait_service_state(state, 1, program::CLIENT_SERVICE_REQUEST_A)?;
    publish_client_service(
        status,
        control,
        &mut status_version,
        program::CLIENT_SERVICE_COMPLETE_RETRY,
        2,
        worker_pids[1],
        2,
        program::CLIENT_SERVICE_REQUEST_A,
    )?;
    publish_client_service(
        status,
        control,
        &mut status_version,
        program::CLIENT_SERVICE_STOP,
        2,
        worker_pids[1],
        2,
        program::CLIENT_SERVICE_REQUEST_A,
    )?;
    expect_client_service_exit(retry, 0, "client service generation 2 outcome")?;
    require_service_state(state, 1, program::CLIENT_SERVICE_REQUEST_A)?;
    let _ = console.write_str("CLIENT GENERATION CHANGE OK\n");

    // Generation 3's status remains monotonic. Its request event deliberately
    // names generation 2; both worker and surviving client classify that
    // event as obsolete without treating generation as kernel authority.
    publish_client_service(
        status,
        control,
        &mut status_version,
        program::CLIENT_SERVICE_COMMAND_STALE,
        3,
        0,
        2,
        program::CLIENT_SERVICE_REQUEST_A,
    )?;
    let stale = spawn_service_worker(status, control, state)
        .map_err(|_| "client service spawn stale generation")?;
    worker_pids[2] = service_worker_pid(stale, client_pid, &worker_pids[..2])?;
    publish_client_service(
        status,
        control,
        &mut status_version,
        program::CLIENT_SERVICE_ACTIVE_STALE,
        3,
        worker_pids[2],
        2,
        program::CLIENT_SERVICE_REQUEST_A,
    )?;
    expect_client_service_exit(stale, 42, "client service stale outcome")?;
    require_service_state(state, 1, program::CLIENT_SERVICE_REQUEST_A)?;
    publish_client_service(
        status,
        control,
        &mut status_version,
        program::CLIENT_SERVICE_STALE_REFUSED,
        3,
        worker_pids[2],
        2,
        program::CLIENT_SERVICE_REQUEST_A,
    )?;
    require_service_state(state, 1, program::CLIENT_SERVICE_REQUEST_A)?;
    let _ = console.write_str("STALE GENERATION REFUSED OK\n");

    // Generation 4 applies B and loses its reply. Generation 5 observes the
    // applied request and proves that replaying the prior expected version
    // is stale, leaving the authoritative cell unchanged.
    publish_client_service(
        status,
        control,
        &mut status_version,
        program::CLIENT_SERVICE_COMMAND_APPLY_FAULT,
        4,
        0,
        4,
        program::CLIENT_SERVICE_REQUEST_B,
    )?;
    let uncertain = spawn_service_worker(status, control, state)
        .map_err(|_| "client service spawn generation 4")?;
    worker_pids[3] = service_worker_pid(uncertain, client_pid, &worker_pids[..3])?;
    publish_client_service(
        status,
        control,
        &mut status_version,
        program::CLIENT_SERVICE_ACTIVE_APPLY_FAULT,
        4,
        worker_pids[3],
        4,
        program::CLIENT_SERVICE_REQUEST_B,
    )?;
    expect_client_service_fault(uncertain, "client service generation 4 outcome")?;
    require_service_state(state, 2, program::CLIENT_SERVICE_REQUEST_B)?;
    publish_client_service(
        status,
        control,
        &mut status_version,
        program::CLIENT_SERVICE_COMMAND_RECONCILE,
        5,
        0,
        5,
        program::CLIENT_SERVICE_REQUEST_B,
    )?;
    let reconcile = spawn_service_worker(status, control, state)
        .map_err(|_| "client service spawn generation 5")?;
    worker_pids[4] = service_worker_pid(reconcile, client_pid, &worker_pids[..4])?;
    publish_client_service(
        status,
        control,
        &mut status_version,
        program::CLIENT_SERVICE_ACTIVE_RECONCILE,
        5,
        worker_pids[4],
        5,
        program::CLIENT_SERVICE_REQUEST_B,
    )?;
    expect_client_service_exit(reconcile, 0, "client service generation 5 outcome")?;
    require_service_state(state, 2, program::CLIENT_SERVICE_REQUEST_B)?;
    publish_client_service(
        status,
        control,
        &mut status_version,
        program::CLIENT_SERVICE_COMPLETE_RECONCILE,
        5,
        worker_pids[4],
        5,
        program::CLIENT_SERVICE_REQUEST_B,
    )?;
    require_service_state(state, 2, program::CLIENT_SERVICE_REQUEST_B)?;
    let _ = console.write_str("CLIENT RECONCILE COMPLETED OK\n");
    let _ = console.write_str("CLIENT NO DOUBLE APPLY OK\n");

    // Generation 6 is the ordinary request/completion path.
    publish_client_service(
        status,
        control,
        &mut status_version,
        program::CLIENT_SERVICE_COMMAND_NORMAL,
        6,
        0,
        6,
        program::CLIENT_SERVICE_REQUEST_C,
    )?;
    let normal = spawn_service_worker(status, control, state)
        .map_err(|_| "client service spawn generation 6")?;
    worker_pids[5] = service_worker_pid(normal, client_pid, &worker_pids[..5])?;
    publish_client_service(
        status,
        control,
        &mut status_version,
        program::CLIENT_SERVICE_ACTIVE_NORMAL,
        6,
        worker_pids[5],
        6,
        program::CLIENT_SERVICE_REQUEST_C,
    )?;
    expect_client_service_exit(normal, 0, "client service generation 6 outcome")?;
    require_service_state(state, 3, program::CLIENT_SERVICE_REQUEST_C)?;
    publish_client_service(
        status,
        control,
        &mut status_version,
        program::CLIENT_SERVICE_COMPLETE_NORMAL,
        6,
        worker_pids[5],
        6,
        program::CLIENT_SERVICE_REQUEST_C,
    )?;
    let _ = console.write_str("CLIENT NORMAL COMPLETION OK\n");

    // Generation 7 leaves D applied before faulting. The active filler prefix
    // occupies every process slot alongside init, client and reserved tasks.
    publish_client_service(
        status,
        control,
        &mut status_version,
        program::CLIENT_SERVICE_COMMAND_APPLY_FAULT,
        7,
        0,
        7,
        program::CLIENT_SERVICE_REQUEST_D,
    )?;
    let pressured = spawn_service_worker(status, control, state)
        .map_err(|_| "client service spawn generation 7")?;
    worker_pids[6] = service_worker_pid(pressured, client_pid, &worker_pids[..6])?;
    publish_client_service(
        status,
        control,
        &mut status_version,
        program::CLIENT_SERVICE_ACTIVE_APPLY_FAULT,
        7,
        worker_pids[6],
        7,
        program::CLIENT_SERVICE_REQUEST_D,
    )?;
    expect_client_service_fault(pressured, "client service generation 7 outcome")?;
    require_service_state(state, 4, program::CLIENT_SERVICE_REQUEST_D)?;
    let full_filler_count = SPAWN_CAPACITY - 1 - reserve;
    let mut full_fillers = [Child::from_raw(0); SPAWN_CAPACITY - 1];
    for filler in &mut full_fillers[..full_filler_count] {
        *filler = spawn(program::EXIT7).map_err(|_| "client service fill all slots")?;
    }
    require_process_count(PROCESS_TABLE_CAPACITY, "client service full census")?;
    publish_client_service(
        status,
        control,
        &mut status_version,
        program::CLIENT_SERVICE_PENDING_CAPACITY,
        8,
        0,
        8,
        program::CLIENT_SERVICE_REQUEST_D,
    )?;
    if spawn_service_worker(status, control, state) != Err(Error::Again) {
        return Err("client service full table refusal");
    }
    require_service_state(state, 4, program::CLIENT_SERVICE_REQUEST_D)?;
    let (_, status_word) = status
        .read()
        .map_err(|_| "client service read pending status")?;
    if status_word != program::client_service_word(program::CLIENT_SERVICE_PENDING_CAPACITY, 8, 0) {
        return Err("client service pending status changed");
    }
    let _ = console.write_str("CLIENT SERVICE UNAVAILABLE OK\n");
    let _ = console.write_str("RECOVERY HEADROOM EXHAUSTED OK\n");

    expect_client_service_exit(full_fillers[0], 7, "client service free one slot")?;
    require_process_count(PROCESS_TABLE_CAPACITY - 1, "client service one-slot census")?;
    let resumed = spawn_service_worker(status, control, state)
        .map_err(|_| "client service resume generation 8")?;
    require_process_count(PROCESS_TABLE_CAPACITY, "client service resumed census")?;
    worker_pids[7] = service_worker_pid(resumed, client_pid, &worker_pids[..7])?;
    publish_client_service(
        status,
        control,
        &mut status_version,
        program::CLIENT_SERVICE_ACTIVE_CAPACITY,
        8,
        worker_pids[7],
        8,
        program::CLIENT_SERVICE_REQUEST_D,
    )?;
    expect_client_service_exit(resumed, 0, "client service generation 8 outcome")?;
    require_service_state(state, 4, program::CLIENT_SERVICE_REQUEST_D)?;
    publish_client_service(
        status,
        control,
        &mut status_version,
        program::CLIENT_SERVICE_COMPLETE_CAPACITY,
        8,
        worker_pids[7],
        8,
        program::CLIENT_SERVICE_REQUEST_D,
    )?;
    require_service_state(state, 4, program::CLIENT_SERVICE_REQUEST_D)?;
    let _ = console.write_str("CLIENT SERVICE RESUME OK\n");
    for filler in &full_fillers[1..full_filler_count] {
        expect_client_service_exit(*filler, 7, "client service drain full fillers")?;
    }
    expect_client_service_process_baseline(reserve)?;

    // The active prefix leaves one process slot beyond init, client and the
    // kernel-reserved qualification processes.
    let headroom_filler_count = SPAWN_CAPACITY - 2 - reserve;
    let mut headroom_fillers = [Child::from_raw(0); SPAWN_CAPACITY - 2];
    for filler in &mut headroom_fillers[..headroom_filler_count] {
        *filler = spawn(program::EXIT7).map_err(|_| "client service fill with headroom")?;
    }
    require_process_count(PROCESS_TABLE_CAPACITY - 1, "client service headroom census")?;
    publish_client_service(
        status,
        control,
        &mut status_version,
        program::CLIENT_SERVICE_PENDING_HEADROOM,
        9,
        0,
        9,
        program::CLIENT_SERVICE_REQUEST_E,
    )?;
    let admitted = spawn_service_worker(status, control, state)
        .map_err(|_| "client service headroom admission")?;
    require_process_count(
        PROCESS_TABLE_CAPACITY,
        "client service headroom admission census",
    )?;
    worker_pids[8] = service_worker_pid(admitted, client_pid, &worker_pids[..8])?;
    publish_client_service(
        status,
        control,
        &mut status_version,
        program::CLIENT_SERVICE_ACTIVE_HEADROOM,
        9,
        worker_pids[8],
        9,
        program::CLIENT_SERVICE_REQUEST_E,
    )?;
    expect_client_service_exit(admitted, 0, "client service generation 9 outcome")?;
    require_service_state(state, 5, program::CLIENT_SERVICE_REQUEST_E)?;
    publish_client_service(
        status,
        control,
        &mut status_version,
        program::CLIENT_SERVICE_COMPLETE_HEADROOM,
        9,
        worker_pids[8],
        9,
        program::CLIENT_SERVICE_REQUEST_E,
    )?;
    let _ = console.write_str("RECOVERY HEADROOM PRESERVED OK\n");
    require_process_count(
        PROCESS_TABLE_CAPACITY - 1,
        "client service post-admission census",
    )?;
    for filler in &headroom_fillers[..headroom_filler_count] {
        expect_client_service_exit(*filler, 7, "client service drain headroom fillers")?;
    }
    expect_client_service_process_baseline(reserve)?;

    // The same client and cells survived all nine worker identities. FINISH
    // is an explicit bounded stop, not process replacement or implicit EOF.
    if info(Some(client))
        .map_err(|_| "client service inspect surviving client")?
        .pid
        != client_pid
        || [status.raw(), control.raw(), state.raw()] != stable_handles
    {
        return Err("client service stable identity");
    }
    publish_client_service(
        status,
        control,
        &mut status_version,
        program::CLIENT_SERVICE_FINISH,
        9,
        0,
        9,
        program::CLIENT_SERVICE_REQUEST_E,
    )?;
    expect_client_service_exit(client, 0, "client service client outcome")?;
    require_service_state(state, 5, program::CLIENT_SERVICE_REQUEST_E)?;
    for left in 0..worker_pids.len() {
        for right in left + 1..worker_pids.len() {
            if worker_pids[left] == worker_pids[right] {
                return Err("client service worker pid reused");
            }
        }
    }
    let _ = console.write_str("CLIENT GENERATION CONTRACT OK\n");
    let _ = console.write_str("CLIENT SERVICE OBJECTS STABLE OK\n");
    let _ = console.write_str("CLIENT SURVIVES SERVICE RESTART OK\n");
    let _ = console.write_str("MULTI GENERATION SERVICE OK\n");

    close(status.raw()).map_err(|_| "client service close status")?;
    close(control.raw()).map_err(|_| "client service close control")?;
    close(state.raw()).map_err(|_| "client service close state")?;
    let reclaim = Cell::create(0x434c_4945_4e54).map_err(|_| "client service reclaim probe")?;
    if reclaim.read() != Ok((0, 0x434c_4945_4e54)) {
        return Err("client service reclaim state");
    }
    close(reclaim.raw()).map_err(|_| "client service close reclaim probe")?;
    Ok(())
}

fn spawn_service_client(status: Cell, control: Cell, state: Cell) -> Result<Child, Error> {
    spawn_many_copy(
        program::SERVICE_CLIENT,
        &[
            SpawnHandleCopy::new(status.raw(), RIGHT_READ),
            SpawnHandleCopy::new(control.raw(), RIGHT_READ | RIGHT_WRITE),
            SpawnHandleCopy::new(state.raw(), RIGHT_READ),
        ],
    )
}

fn spawn_service_worker(status: Cell, control: Cell, state: Cell) -> Result<Child, Error> {
    spawn_many_copy(
        program::CLIENT_SERVICE_WORKER,
        &[
            SpawnHandleCopy::new(status.raw(), RIGHT_READ),
            SpawnHandleCopy::new(control.raw(), RIGHT_READ),
            SpawnHandleCopy::new(state.raw(), RIGHT_READ | RIGHT_WRITE),
        ],
    )
}

fn service_worker_pid(child: Child, client_pid: u64, prior: &[u64]) -> Result<u64, &'static str> {
    let record = info(Some(child)).map_err(|_| "client service inspect worker")?;
    if record.pid == client_pid
        || prior.contains(&record.pid)
        || record.program != program::CLIENT_SERVICE_WORKER
        || (record.state != INFO_STATE_LIVE
            && record.state != INFO_STATE_WAITING
            && record.state != INFO_STATE_TERMINAL)
    {
        return Err("client service worker identity");
    }
    Ok(record.pid)
}

#[allow(clippy::too_many_arguments)]
fn publish_client_service(
    status: Cell,
    control: Cell,
    status_version: &mut u64,
    phase: u64,
    generation: u64,
    worker_pid: u64,
    event_generation: u64,
    request: u64,
) -> Result<(), &'static str> {
    let published = program::client_service_word(phase, generation, worker_pid);
    let next = status
        .transition(*status_version, published)
        .map_err(|_| "client service publish status")?;
    if next != *status_version + 1 {
        return Err("client service status version");
    }
    *status_version = next;

    let expected = program::client_service_word(phase, event_generation, request);
    let deadline = time().saturating_add(SUPERVISOR_WAIT_TICKS);
    loop {
        let (seen, value) = control
            .read()
            .map_err(|_| "client service read acknowledgement")?;
        if value == expected {
            return Ok(());
        }
        let now = time();
        if now >= deadline {
            return Err("client service acknowledgement timeout");
        }
        match control.wait_change_timeout(seen, deadline - now) {
            Ok(_) => {}
            Err(Error::Timeout) => return Err("client service acknowledgement timeout"),
            Err(_) => return Err("client service acknowledgement wait"),
        }
    }
}

fn wait_service_state(cell: Cell, version: u64, value: u64) -> Result<(), &'static str> {
    let deadline = time().saturating_add(SUPERVISOR_WAIT_TICKS);
    loop {
        let (seen, observed) = cell.read().map_err(|_| "client service read state")?;
        if (seen, observed) == (version, value) {
            return Ok(());
        }
        if seen > version {
            return Err("client service state advanced unexpectedly");
        }
        let now = time();
        if now >= deadline {
            return Err("client service state timeout");
        }
        match cell.wait_change_timeout(seen, deadline - now) {
            Ok(_) => {}
            Err(Error::Timeout) => return Err("client service state timeout"),
            Err(_) => return Err("client service state wait"),
        }
    }
}

fn require_service_state(cell: Cell, version: u64, value: u64) -> Result<(), &'static str> {
    if cell.read() == Ok((version, value)) {
        Ok(())
    } else {
        Err("client service state changed")
    }
}

fn expect_client_service_fault(child: Child, step: &'static str) -> Result<(), &'static str> {
    match wait_timeout(Some(child), SUPERVISOR_WAIT_TICKS) {
        Ok(Outcome::Faulted {
            vector: VECTOR_INVALID_OPCODE,
            error: 0,
            ..
        }) => {}
        Ok(_) => return Err(step),
        Err(Error::Timeout) => {
            kill(child).map_err(|_| "client service kill timed-out fault")?;
            let _ = wait_timeout(Some(child), SUPERVISOR_WAIT_TICKS);
            return Err("client service fault timeout");
        }
        Err(_) => return Err("client service fault wait"),
    }
    if info(Some(child)) != Err(Error::BadHandle) {
        return Err("client service fault handle remained live");
    }
    Ok(())
}

fn expect_client_service_exit(
    child: Child,
    status: i32,
    step: &'static str,
) -> Result<(), &'static str> {
    match wait_timeout(Some(child), SUPERVISOR_WAIT_TICKS) {
        Ok(Outcome::Exited(actual)) if actual == status => {}
        Ok(_) => return Err(step),
        Err(Error::Timeout) => {
            kill(child).map_err(|_| "client service kill timed-out exit")?;
            let _ = wait_timeout(Some(child), SUPERVISOR_WAIT_TICKS);
            return Err("client service exit timeout");
        }
        Err(_) => return Err("client service exit wait"),
    }
    if info(Some(child)) != Err(Error::BadHandle) {
        return Err("client service exit handle remained live");
    }
    Ok(())
}

fn spawn_recovery(cell: Cell, generation: u64, request: u64, mode: u64) -> Result<Child, Error> {
    let granted = duplicate(cell.raw(), RIGHT_READ | RIGHT_WRITE)?;
    let argument = program::recovery_arg(mode, generation, request);
    let spawned = spawn_with(program::RECOVERY_WORKER, granted, argument);
    if let Err(error) = close(granted) {
        if let Ok(child) = spawned {
            let _ = kill(child);
            let _ = wait_timeout(Some(child), SUPERVISOR_WAIT_TICKS);
        }
        return Err(error);
    }
    spawned
}

fn spawn_recovery_live(
    cell: Cell,
    generation: u64,
    request: u64,
    mode: u64,
) -> Result<(Child, u64), &'static str> {
    let child =
        spawn_recovery(cell, generation, request, mode).map_err(|_| "recovery worker spawn")?;
    let pid = info(Some(child))
        .map_err(|_| "inspect recovery worker")?
        .pid;
    Ok((child, pid))
}

fn report_recovery_instance(console: Console, generation: u64, pid: u64, request: u64) {
    let _ = absd_user::cprintln!(
        console,
        "SERVICE INSTANCE service=test generation={} pid={} request={}",
        generation,
        pid,
        request
    );
}

fn expect_recovery_fault(child: Child, wrong_fault: &'static str) -> Result<(), &'static str> {
    match wait_timeout(Some(child), SUPERVISOR_WAIT_TICKS) {
        Ok(Outcome::Faulted {
            vector: VECTOR_INVALID_OPCODE,
            error: 0,
            ..
        }) => {}
        Ok(Outcome::Faulted { .. }) => return Err(wrong_fault),
        Ok(Outcome::Exited(_)) => return Err("recovery worker unexpectedly exited"),
        Ok(Outcome::Killed) => return Err("recovery worker unexpectedly killed"),
        Err(Error::Timeout) => {
            kill(child).map_err(|_| "kill timed-out recovery worker")?;
            match wait_timeout(Some(child), SUPERVISOR_WAIT_TICKS) {
                Ok(Outcome::Killed) => return Err("recovery fault timed out"),
                _ => return Err("reap timed-out recovery worker"),
            }
        }
        Err(_) => return Err("recovery fault wait"),
    }
    if info(Some(child)) != Err(Error::BadHandle) {
        return Err("recovery fault handle remained live");
    }
    Ok(())
}

fn expect_recovery_exit(child: Child, wrong_exit: &'static str) -> Result<(), &'static str> {
    match wait_timeout(Some(child), SUPERVISOR_WAIT_TICKS) {
        Ok(Outcome::Exited(0)) => {}
        Ok(Outcome::Exited(_)) => return Err(wrong_exit),
        Ok(Outcome::Faulted { .. }) => return Err("recovery worker faulted"),
        Ok(Outcome::Killed) => return Err("recovery worker killed"),
        Err(Error::Timeout) => {
            kill(child).map_err(|_| "kill timed-out recovery completion")?;
            match wait_timeout(Some(child), SUPERVISOR_WAIT_TICKS) {
                Ok(Outcome::Killed) => return Err("recovery completion timed out"),
                _ => return Err("reap timed-out recovery completion"),
            }
        }
        Err(_) => return Err("recovery completion wait"),
    }
    if info(Some(child)) != Err(Error::BadHandle) {
        return Err("recovery exit handle remained live");
    }
    Ok(())
}

/// Starts one worker and returns the exact userspace spawn error. The
/// temporary authority is closed after the syscall on both result paths.
fn spawn_supervised(cell: Cell, generation: u64) -> Result<Child, Error> {
    spawn_supervised_with_rights(
        cell,
        RIGHT_WRITE,
        program::SUPERVISED_MODE_TRANSITION,
        generation,
    )
}

fn spawn_supervised_control(cell: Cell, mode: u64, generation: u64) -> Result<Child, &'static str> {
    spawn_supervised_with_rights(cell, RIGHT_READ, mode, generation)
        .map_err(|_| "supervisor control spawn failure")
}

fn spawn_supervised_with_rights(
    cell: Cell,
    rights: u64,
    mode: u64,
    generation: u64,
) -> Result<Child, Error> {
    let granted = duplicate(cell.raw(), rights)?;
    let argument = program::supervised_arg(mode, generation);
    let spawned = spawn_with(program::SUPERVISED_WORKER, granted, argument);
    if let Err(error) = close(granted) {
        // This cannot occur for the fresh duplicate above. If the invariant is
        // ever broken after a successful spawn, do not abandon a live child.
        if let Ok(child) = spawned {
            let _ = kill(child);
            let _ = wait_timeout(Some(child), SUPERVISOR_WAIT_TICKS);
        }
        return Err(error);
    }
    spawned
}

fn spawn_supervised_live(cell: Cell, generation: u64) -> Result<(Child, u64), &'static str> {
    let child = spawn_supervised(cell, generation).map_err(|_| "supervisor spawn failure")?;
    let pid = info(Some(child))
        .map_err(|_| "supervisor inspect fresh worker")?
        .pid;
    Ok((child, pid))
}

fn report_supervised_instance(console: Console, generation: u64, pid: u64) {
    let _ = absd_user::cprintln!(
        console,
        "SUPERVISOR INSTANCE generation={} pid={}",
        generation,
        pid
    );
}

fn expect_supervised_fault(child: Child, wrong_fault: &'static str) -> Result<(), &'static str> {
    match wait_timeout(Some(child), SUPERVISOR_WAIT_TICKS) {
        Ok(Outcome::Faulted {
            vector: VECTOR_INVALID_OPCODE,
            error: 0,
            ..
        }) => {}
        Ok(Outcome::Faulted { .. }) => return Err(wrong_fault),
        Ok(Outcome::Exited(_)) => return Err("supervisor unexpected exit"),
        Ok(Outcome::Killed) => return Err("supervisor unexpected kill"),
        Err(Error::Timeout) => {
            kill(child).map_err(|_| "supervisor kill stuck fault worker")?;
            match wait_timeout(Some(child), SUPERVISOR_WAIT_TICKS) {
                Ok(Outcome::Killed) => return Err("supervisor fault worker timed out"),
                _ => return Err("supervisor reap stuck fault worker"),
            }
        }
        Err(_) => return Err("supervisor fault wait"),
    }
    if info(Some(child)) != Err(Error::BadHandle) {
        return Err("supervisor fault handle remained live");
    }
    Ok(())
}

fn expect_supervised_exit(child: Child) -> Result<(), &'static str> {
    match wait_timeout(Some(child), SUPERVISOR_WAIT_TICKS) {
        Ok(Outcome::Exited(0)) => {}
        Ok(Outcome::Exited(_)) => return Err("supervisor replacement status"),
        Ok(Outcome::Faulted { .. }) => return Err("supervisor replacement fault"),
        Ok(Outcome::Killed) => return Err("supervisor replacement killed"),
        Err(Error::Timeout) => {
            kill(child).map_err(|_| "supervisor kill stuck replacement")?;
            match wait_timeout(Some(child), SUPERVISOR_WAIT_TICKS) {
                Ok(Outcome::Killed) => return Err("supervisor replacement timed out"),
                _ => return Err("supervisor reap stuck replacement"),
            }
        }
        Err(_) => return Err("supervisor replacement wait"),
    }
    if info(Some(child)) != Err(Error::BadHandle) {
        return Err("supervisor exit handle remained live");
    }
    Ok(())
}

/// Fills init's own handle table without creating distinct objects. The ABI's
/// spawn-transfer bound deliberately equals one complete handle table, so it
/// is also the userspace-visible bound for this pressure test.
fn verify_handle_capacity(console: Console) -> Result<(), &'static str> {
    let anchor = Cell::create(0x4841_4e44_4c45).map_err(|_| "handle capacity anchor")?;
    let mut held = [0u64; MAX_SPAWN_HANDLES];
    let mut count = 0;
    loop {
        match duplicate(anchor.raw(), RIGHT_READ) {
            Ok(handle) => {
                held[count] = handle;
                count += 1;
            }
            Err(Error::TooManyHandles) => break,
            Err(_) => return Err("handle capacity fill"),
        }
        if count == held.len() {
            return Err("handle table exceeded ABI bound");
        }
    }
    // Console, the machine handle, and the anchor occupy three slots; every
    // remaining slot must have received one duplicate, with no existing
    // entry overwritten.
    if count != MAX_SPAWN_HANDLES - 3 || anchor.read() != Ok((0, 0x4841_4e44_4c45)) {
        return Err("handle capacity size");
    }
    for &handle in &held[..count] {
        if Cell::from_raw(handle).read() != Ok((0, 0x4841_4e44_4c45)) {
            return Err("handle capacity overwrite");
        }
    }

    // Every operation that needs a new caller-side handle fails before it
    // can publish an object or child. Spawn-many's child-capacity rollback is
    // independently covered by verify_multi_handle_spawn above.
    if Cell::create(1) != Err(Error::TooManyHandles)
        || Pipe::create() != Err(Error::TooManyHandles)
        || spawn(program::EXIT7) != Err(Error::TooManyHandles)
        || spawn_many_copy(program::MULTI_HANDLE, &[]) != Err(Error::TooManyHandles)
    {
        return Err("handle capacity refusal");
    }

    let stale = held[count - 1];
    close(stale).map_err(|_| "handle capacity free slot")?;
    count -= 1;
    if close(stale) != Err(Error::BadHandle) {
        return Err("handle capacity stale value");
    }
    let replacement =
        duplicate(anchor.raw(), RIGHT_READ).map_err(|_| "handle capacity immediate reuse")?;
    if replacement == stale || Cell::from_raw(replacement).read() != Ok((0, 0x4841_4e44_4c45)) {
        return Err("handle capacity replacement");
    }
    if duplicate(anchor.raw(), RIGHT_READ) != Err(Error::TooManyHandles) {
        return Err("handle capacity refill boundary");
    }

    close(replacement).map_err(|_| "handle capacity close replacement")?;
    for &handle in &held[..count] {
        close(handle).map_err(|_| "handle capacity drain")?;
    }
    close(anchor.raw()).map_err(|_| "handle capacity close anchor")?;
    let _ = console.write_str("HANDLE CAPACITY OK\n");
    Ok(())
}

/// Finds the cell and pipe table boundaries through their public allocation
/// failures, then repeatedly proves that freeing one object makes exactly one
/// slot immediately reusable. No kernel-private capacity is copied here.
fn verify_object_capacity(console: Console) -> Result<(), &'static str> {
    for cycle in 0..OBJECT_CAPACITY_CYCLES as u64 {
        let mut held = [Cell::from_raw(0); MAX_SPAWN_HANDLES];
        let mut count = 0;
        loop {
            match Cell::create(cycle) {
                Ok(cell) => {
                    held[count] = cell;
                    count += 1;
                }
                Err(Error::NoMemory) => break,
                Err(_) => return Err("cell object capacity fill"),
            }
            if count == held.len() {
                return Err("cell object capacity unbounded");
            }
        }
        if count == 0 {
            return Err("cell object capacity zero");
        }
        let stale = held[0].raw();
        close(stale).map_err(|_| "cell object capacity free")?;
        let replacement = Cell::create(0xc000 + cycle).map_err(|_| "cell object capacity reuse")?;
        if replacement.raw() == stale || replacement.read() != Ok((0, 0xc000 + cycle)) {
            return Err("cell object capacity replacement");
        }
        if Cell::create(0) != Err(Error::NoMemory) {
            return Err("cell object capacity refill boundary");
        }
        close(replacement.raw()).map_err(|_| "cell object capacity close replacement")?;
        for cell in &held[1..count] {
            close(cell.raw()).map_err(|_| "cell object capacity drain")?;
        }
    }

    for _ in 0..OBJECT_CAPACITY_CYCLES {
        let mut held = [Pipe::from_raw(0); MAX_SPAWN_HANDLES];
        let mut count = 0;
        loop {
            match Pipe::create() {
                Ok(pipe) => {
                    held[count] = pipe;
                    count += 1;
                }
                Err(Error::NoMemory) => break,
                Err(_) => return Err("pipe object capacity fill"),
            }
            if count == held.len() {
                return Err("pipe object capacity unbounded");
            }
        }
        if count == 0 {
            return Err("pipe object capacity zero");
        }
        let stale = held[0].raw();
        close(stale).map_err(|_| "pipe object capacity free")?;
        let replacement = Pipe::create().map_err(|_| "pipe object capacity reuse")?;
        let mut byte = [0u8; 1];
        if replacement.raw() == stale
            || replacement.write_once(b"p") != Ok(1)
            || replacement.read_once(&mut byte) != Ok(1)
            || byte != *b"p"
        {
            return Err("pipe object capacity replacement");
        }
        if Pipe::create() != Err(Error::NoMemory) {
            return Err("pipe object capacity refill boundary");
        }
        close(replacement.raw()).map_err(|_| "pipe object capacity close replacement")?;
        for pipe in &held[1..count] {
            close(pipe.raw()).map_err(|_| "pipe object capacity drain")?;
        }
    }
    let _ = console.write_str("OBJECT CAPACITY OK\n");
    Ok(())
}

fn expect_exit(child: Child, status: i32, step: &'static str) -> Result<(), &'static str> {
    match wait(Some(child)) {
        Ok(Outcome::Exited(actual)) if actual == status => Ok(()),
        _ => Err(step),
    }
}

/// Wait until a child is observably blocked rather than guessing from a
/// scheduling delay. Cell waiters remain blocked until explicitly changed or
/// killed, so this bounded poll makes kill-while-blocked deterministic.
fn expect_waiting(child: Child, step: &'static str) -> Result<(), &'static str> {
    let deadline = time().saturating_add(SUPERVISOR_WAIT_TICKS);
    loop {
        match info(Some(child)) {
            Ok(record) if record.state == INFO_STATE_WAITING => return Ok(()),
            Ok(record) if record.state == INFO_STATE_LIVE && time() < deadline => yield_now(),
            _ => return Err(step),
        }
    }
}

/// A present/write/user page fault from the `fault` program.
fn expect_fault(child: Child, step: &'static str) -> Result<(), &'static str> {
    match wait(Some(child)) {
        Ok(Outcome::Faulted {
            vector: VECTOR_PAGE_FAULT,
            error,
            ..
        }) if error & 7 == 7 => Ok(()),
        _ => Err(step),
    }
}

/// The `fpu-test` boot (docs/HOSTILE-USERSPACE.md): two tasks holding
/// distinct MXCSR configurations and XMM sentinels across yields and timer
/// preemptions; one task faulting on a deliberately unmasked SIMD exception;
/// and witness tasks proving a fresh process sees the kernel's default
/// control state after a predecessor's fault, ordinary exit, and kill.
fn run_fpu_test(console: Console) -> Result<(), &'static str> {
    // 1. MXCSR isolation across context switches: two concurrent tasks with
    // deliberately distinct rounding control and FTZ/DAZ configuration, each
    // verifying its own state (and rounding-sensitive arithmetic) after every
    // switch.
    let task_a = spawn_with(program::FPU_MXCSR, 0, 0).map_err(|_| "fpu task A spawn")?;
    let task_b = spawn_with(program::FPU_MXCSR, 0, 1).map_err(|_| "fpu task B spawn")?;
    expect_exit(task_a, 0, "fpu task A outcome")?;
    expect_exit(task_b, 0, "fpu task B outcome")?;
    let _ = console.write_str("FPU MXCSR ISOLATION OK\n");

    // 2. An unmasked SSE divide-by-zero must end exactly this task with #XM
    // (vector 19), and the next task must not inherit its control state.
    let faulted = spawn_with(program::FPU_MXCSR, 0, 2).map_err(|_| "fpu xm spawn")?;
    match wait(Some(faulted)) {
        Ok(Outcome::Faulted {
            vector: VECTOR_SIMD_ERROR,
            error: 0,
            ..
        }) => {}
        _ => return Err("fpu xm outcome"),
    }
    let _ = console.write_str("FPU XM FAULT OK\n");
    let witness = spawn_with(program::FPU_MXCSR, 0, 3).map_err(|_| "fpu post-fault spawn")?;
    expect_exit(witness, 0, "fpu post-fault witness outcome")?;
    let _ = console.write_str("FPU POST-FAULT WITNESS OK\n");

    // 3a. Ordinary exit while holding distinctive FPU state, then a witness.
    let exited = spawn_with(program::FPU_MXCSR, 0, 4).map_err(|_| "fpu dirty exit spawn")?;
    expect_exit(exited, 0, "fpu dirty exit outcome")?;
    let witness = spawn_with(program::FPU_MXCSR, 0, 3).map_err(|_| "fpu post-exit spawn")?;
    expect_exit(witness, 0, "fpu post-exit witness outcome")?;
    let _ = console.write_str("FPU EXIT WITNESS OK\n");

    // 3b. Kill while the task holds distinctive FPU state, then a witness.
    // The sleep window lets the looping task run and install its state
    // before the kill lands; it can never exit on its own.
    let looper = spawn_with(program::FPU_MXCSR, 0, 5).map_err(|_| "fpu dirty loop spawn")?;
    sleep(10);
    kill(looper).map_err(|_| "fpu dirty loop kill")?;
    match wait(Some(looper)) {
        Ok(Outcome::Killed) => {}
        _ => return Err("fpu dirty loop outcome"),
    }
    let witness = spawn_with(program::FPU_MXCSR, 0, 3).map_err(|_| "fpu post-kill spawn")?;
    expect_exit(witness, 0, "fpu post-kill witness outcome")?;
    let _ = console.write_str("FPU KILL WITNESS OK\n");
    Ok(())
}

// Sequential scenarios share one continuously runnable non-yielding hog.
fn run_rt_test(console: Console) -> Result<(), &'static str> {
    // Closed fixture quiet start, before any RT object exists.
    // Retained default KVM delivery can have boot-time timer debt.
    sleep(100);
    let hog = spawn_with(program::RT_PROBE, 0, 0).map_err(|_| "rt hog spawn")?;
    for mode in [1, 2] {
        let _ = console.write_str(if mode == 1 {
            "RT SCENARIO mode=1\n"
        } else {
            "RT SCENARIO mode=2\n"
        });
        let rt = spawn_with(program::RT_PROBE, 0, mode).map_err(|_| "rt spawn")?;
        sleep(270);
        kill(rt).map_err(|_| "rt kill")?;
        match wait(Some(rt)).map_err(|_| "rt reap")? {
            Outcome::Killed => (),
            _ => return Err("rt unexpectedly ended"),
        }
    }
    kill(hog).map_err(|_| "hog kill")?;
    match wait(Some(hog)).map_err(|_| "hog reap")? {
        Outcome::Killed => Ok(()),
        _ => Err("hog unexpectedly ended"),
    }
}

fn run_smp_lifecycle(console: Console) -> Result<(), &'static str> {
    // Each published child is claimed exclusively by the kernel-only AP
    // before this spawn returns. The real kill/wait syscalls then exercise
    // StopFence, post-departure reclaim and one terminal outcome.
    for phase in 0..4 {
        let child =
            spawn_with(program::SLEEPER, 0, 1000).map_err(|_| "SMP lifecycle child spawn")?;
        let _ = console.line(format_args!("SMP LIFECYCLE PHASE {phase}\n"));
        kill(child).map_err(|_| "SMP lifecycle stop")?;
        match wait(Some(child)).map_err(|_| "SMP lifecycle wait")? {
            Outcome::Killed => {}
            _ => return Err("SMP lifecycle outcome"),
        }
    }
    Ok(())
}

fn run_rt_class(console: Console) -> Result<(), &'static str> {
    // Closed fixture quiet start, before any RT object exists.
    // Retained default KVM delivery can have boot-time timer debt.
    sleep(100);
    // An ordinary caller cannot enter the class through its completion operation.
    if absd_user::rt_next() != Err(Error::Invalid) {
        return Err("ordinary RT operation accepted");
    }
    for scenario in 1..=12 {
        let _ = console.line(format_args!("RT CASE id={scenario}\n"));
        let hog = if scenario == 7 {
            None
        } else {
            Some(spawn_with(program::RT_PROBE, 0, 0).map_err(|_| "class hog spawn")?)
        };
        let modes: &[u64] = match scenario {
            1 | 7 => &[1],
            2 => &[2],
            3 => &[3],
            4 => &[4],
            5 => &[5],
            6 => &[6],
            8 => &[8],
            9 => &[9, 9],
            10 => &[10, 13],
            11 => &[11],
            _ => &[12],
        };
        let mut children = [None; 2];
        for (slot, &mode) in modes.iter().enumerate() {
            children[slot] =
                Some(spawn_with(program::RT_PROBE, 0, mode).map_err(|_| "class RT spawn")?);
        }
        sleep(270);
        for child in children.into_iter().flatten() {
            kill(child).map_err(|_| "class RT kill")?;
            match wait(Some(child)).map_err(|_| "class RT reap")? {
                Outcome::Killed if scenario != 12 => (),
                Outcome::Faulted {
                    vector: VECTOR_INVALID_OPCODE,
                    ..
                } if scenario == 12 => (),
                _ => return Err("class RT outcome"),
            }
        }
        if let Some(hog) = hog {
            kill(hog).map_err(|_| "class hog kill")?;
            match wait(Some(hog)).map_err(|_| "class hog reap")? {
                Outcome::Killed => (),
                _ => return Err("class hog outcome"),
            }
        }
    }
    let _ = console.write_str("RT CLASS CASES OK\n");
    Ok(())
}
