//! Long-lived client for the userspace-only service replacement experiment.
//! The three inherited cells keep their identity while every service worker
//! gets a fresh process identity and an explicit copy of the same authority.
#![no_std]
#![no_main]

use absd_user::{Cell, Error, MultiStart, getpid, program, time};

const INACTIVITY_TICKS: u64 = 5_000;

// Init waits for an acknowledgement after each publication, so the client
// must observe this exact script without skipped states. Generation 7 reuses
// the apply-then-fault phases for the later capacity-pressure request.
const SCRIPT: [(u64, u64); 27] = [
    (program::CLIENT_SERVICE_COMMAND_FAULT, 1),
    (program::CLIENT_SERVICE_ACTIVE_FAULT, 1),
    (program::CLIENT_SERVICE_UNAVAILABLE, 1),
    (program::CLIENT_SERVICE_COMMAND_RETRY, 2),
    (program::CLIENT_SERVICE_ACTIVE_RETRY, 2),
    (program::CLIENT_SERVICE_COMPLETE_RETRY, 2),
    (program::CLIENT_SERVICE_STOP, 2),
    (program::CLIENT_SERVICE_COMMAND_STALE, 3),
    (program::CLIENT_SERVICE_ACTIVE_STALE, 3),
    (program::CLIENT_SERVICE_STALE_REFUSED, 3),
    (program::CLIENT_SERVICE_COMMAND_APPLY_FAULT, 4),
    (program::CLIENT_SERVICE_ACTIVE_APPLY_FAULT, 4),
    (program::CLIENT_SERVICE_COMMAND_RECONCILE, 5),
    (program::CLIENT_SERVICE_ACTIVE_RECONCILE, 5),
    (program::CLIENT_SERVICE_COMPLETE_RECONCILE, 5),
    (program::CLIENT_SERVICE_COMMAND_NORMAL, 6),
    (program::CLIENT_SERVICE_ACTIVE_NORMAL, 6),
    (program::CLIENT_SERVICE_COMPLETE_NORMAL, 6),
    (program::CLIENT_SERVICE_COMMAND_APPLY_FAULT, 7),
    (program::CLIENT_SERVICE_ACTIVE_APPLY_FAULT, 7),
    (program::CLIENT_SERVICE_PENDING_CAPACITY, 8),
    (program::CLIENT_SERVICE_ACTIVE_CAPACITY, 8),
    (program::CLIENT_SERVICE_COMPLETE_CAPACITY, 8),
    (program::CLIENT_SERVICE_PENDING_HEADROOM, 9),
    (program::CLIENT_SERVICE_ACTIVE_HEADROOM, 9),
    (program::CLIENT_SERVICE_COMPLETE_HEADROOM, 9),
    (program::CLIENT_SERVICE_FINISH, 9),
];

absd_user::multi_entry!(main);

fn request_for_phase(phase: u64, generation: u64) -> Option<u64> {
    match phase {
        program::CLIENT_SERVICE_COMMAND_FAULT
        | program::CLIENT_SERVICE_ACTIVE_FAULT
        | program::CLIENT_SERVICE_UNAVAILABLE
        | program::CLIENT_SERVICE_COMMAND_RETRY
        | program::CLIENT_SERVICE_ACTIVE_RETRY
        | program::CLIENT_SERVICE_COMPLETE_RETRY
        | program::CLIENT_SERVICE_STOP
        | program::CLIENT_SERVICE_COMMAND_STALE
        | program::CLIENT_SERVICE_ACTIVE_STALE
        | program::CLIENT_SERVICE_STALE_REFUSED => Some(program::CLIENT_SERVICE_REQUEST_A),
        program::CLIENT_SERVICE_COMMAND_APPLY_FAULT
        | program::CLIENT_SERVICE_ACTIVE_APPLY_FAULT
            if generation == 7 =>
        {
            Some(program::CLIENT_SERVICE_REQUEST_D)
        }
        program::CLIENT_SERVICE_COMMAND_APPLY_FAULT
        | program::CLIENT_SERVICE_ACTIVE_APPLY_FAULT
        | program::CLIENT_SERVICE_COMMAND_RECONCILE
        | program::CLIENT_SERVICE_ACTIVE_RECONCILE
        | program::CLIENT_SERVICE_COMPLETE_RECONCILE => Some(program::CLIENT_SERVICE_REQUEST_B),
        program::CLIENT_SERVICE_COMMAND_NORMAL
        | program::CLIENT_SERVICE_ACTIVE_NORMAL
        | program::CLIENT_SERVICE_COMPLETE_NORMAL => Some(program::CLIENT_SERVICE_REQUEST_C),
        program::CLIENT_SERVICE_PENDING_CAPACITY
        | program::CLIENT_SERVICE_ACTIVE_CAPACITY
        | program::CLIENT_SERVICE_COMPLETE_CAPACITY => Some(program::CLIENT_SERVICE_REQUEST_D),
        program::CLIENT_SERVICE_PENDING_HEADROOM
        | program::CLIENT_SERVICE_ACTIVE_HEADROOM
        | program::CLIENT_SERVICE_COMPLETE_HEADROOM
        | program::CLIENT_SERVICE_FINISH => Some(program::CLIENT_SERVICE_REQUEST_E),
        _ => None,
    }
}

fn main(start: MultiStart<'_>) -> i32 {
    let [status_raw, control_raw, state_raw] = start.handles else {
        return 110;
    };
    // Spawn grants status/state read-only and request/control read-write. The
    // client never receives a process handle or service-state write authority.
    let original_handles = [*status_raw, *control_raw, *state_raw];
    let status = Cell::from_raw(*status_raw);
    let control = Cell::from_raw(*control_raw);
    let state = Cell::from_raw(*state_raw);
    if status.transition(0, 0) != Err(Error::Rights) || state.transition(0, 0) != Err(Error::Rights)
    {
        return 109;
    }
    let original_pid = getpid();
    let mut deadline = time().saturating_add(INACTIVITY_TICKS);
    let mut status_version = 0;
    let mut last_generation = 0;
    let mut last_worker_pid = 0;
    let mut worker_pids = [0u64; 9];
    let mut worker_count = 0;
    let mut script_index = 0;
    let mut saw_retry_not_performed = false;
    let mut saw_stale_refusal = false;
    let mut saw_reconcile = false;
    let mut saw_normal = false;
    let mut saw_capacity_unavailable = false;
    let mut saw_capacity_resume = false;
    let mut saw_headroom = false;

    loop {
        let now = time();
        if now >= deadline {
            return 111;
        }
        if status
            .wait_change_timeout(status_version, deadline - now)
            .is_err()
        {
            return 111;
        }
        let Ok((new_version, word)) = status.read() else {
            return 112;
        };
        if new_version <= status_version {
            return 113;
        }
        status_version = new_version;
        deadline = time().saturating_add(INACTIVITY_TICKS);
        let phase = program::client_service_phase(word);
        let generation = program::client_service_generation(word);
        let worker_pid = program::client_service_value(word);
        if SCRIPT.get(script_index) != Some(&(phase, generation)) {
            return 114;
        }
        script_index += 1;
        let Some(request) = request_for_phase(phase, generation) else {
            return 114;
        };
        if generation < last_generation {
            return 115;
        }

        let active = matches!(
            phase,
            program::CLIENT_SERVICE_ACTIVE_FAULT
                | program::CLIENT_SERVICE_ACTIVE_RETRY
                | program::CLIENT_SERVICE_ACTIVE_STALE
                | program::CLIENT_SERVICE_ACTIVE_APPLY_FAULT
                | program::CLIENT_SERVICE_ACTIVE_RECONCILE
                | program::CLIENT_SERVICE_ACTIVE_NORMAL
                | program::CLIENT_SERVICE_ACTIVE_CAPACITY
                | program::CLIENT_SERVICE_ACTIVE_HEADROOM
        );
        if active {
            if worker_pid == 0
                || (generation > last_generation
                    && last_worker_pid != 0
                    && worker_pid == last_worker_pid)
                || worker_pids[..worker_count].contains(&worker_pid)
            {
                return 116;
            }
            if worker_count == worker_pids.len() {
                return 116;
            }
            worker_pids[worker_count] = worker_pid;
            worker_count += 1;
            last_worker_pid = worker_pid;
            last_generation = generation;
        }

        let expected_state = match phase {
            program::CLIENT_SERVICE_UNAVAILABLE => {
                saw_retry_not_performed = true;
                Some((0, 0))
            }
            program::CLIENT_SERVICE_COMPLETE_RETRY | program::CLIENT_SERVICE_STOP => {
                Some((1, program::CLIENT_SERVICE_REQUEST_A))
            }
            program::CLIENT_SERVICE_STALE_REFUSED => {
                saw_stale_refusal = true;
                Some((1, program::CLIENT_SERVICE_REQUEST_A))
            }
            program::CLIENT_SERVICE_COMPLETE_RECONCILE => {
                saw_reconcile = true;
                Some((2, program::CLIENT_SERVICE_REQUEST_B))
            }
            program::CLIENT_SERVICE_COMPLETE_NORMAL => {
                saw_normal = true;
                Some((3, program::CLIENT_SERVICE_REQUEST_C))
            }
            program::CLIENT_SERVICE_PENDING_CAPACITY => {
                saw_capacity_unavailable = true;
                Some((4, program::CLIENT_SERVICE_REQUEST_D))
            }
            program::CLIENT_SERVICE_COMPLETE_CAPACITY => {
                saw_capacity_resume = true;
                Some((4, program::CLIENT_SERVICE_REQUEST_D))
            }
            program::CLIENT_SERVICE_COMPLETE_HEADROOM => {
                saw_headroom = true;
                Some((5, program::CLIENT_SERVICE_REQUEST_E))
            }
            _ => None,
        };
        if let Some(expected) = expected_state {
            let Ok(observed) = state.read() else {
                return 117;
            };
            if observed != expected {
                return 118;
            }
        }

        // The obsolete generation is deliberately carried in the event cell;
        // the authoritative status directory remains monotonic at generation 3.
        let event_generation = if matches!(
            phase,
            program::CLIENT_SERVICE_COMMAND_STALE
                | program::CLIENT_SERVICE_ACTIVE_STALE
                | program::CLIENT_SERVICE_STALE_REFUSED
        ) {
            generation.saturating_sub(1)
        } else {
            generation
        };
        let Ok((control_version, _)) = control.read() else {
            return 119;
        };
        if control
            .transition(
                control_version,
                program::client_service_word(phase, event_generation, request),
            )
            .is_err()
        {
            return 120;
        }

        if phase == program::CLIENT_SERVICE_FINISH {
            if getpid() != original_pid
                || [status.raw(), control.raw(), state.raw()] != original_handles
                || script_index != SCRIPT.len()
                || worker_count != worker_pids.len()
                || last_generation < 9
                || !saw_retry_not_performed
                || !saw_stale_refusal
                || !saw_reconcile
                || !saw_normal
                || !saw_capacity_unavailable
                || !saw_capacity_resume
                || !saw_headroom
            {
                return 121;
            }
            let _ = absd_user::cprintln!(
                start.console,
                "SERVICE CLIENT COMPLETE pid={} generations={}",
                original_pid,
                last_generation
            );
            return 0;
        }
    }
}
