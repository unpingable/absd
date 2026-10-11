//! One replaceable service instance. Startup metadata is published through
//! cells after spawn because the multi-handle entry ABI intentionally carries
//! only its ordered handle vector.
#![no_std]
#![no_main]

use absd_user::{Cell, Error, MultiStart, getpid, program, time};
use core::arch::asm;

const WAIT_TICKS: u64 = 1_000;

absd_user::multi_entry!(main);

fn intentional_fault() -> ! {
    unsafe { asm!("ud2", options(noreturn, nostack)) }
}

fn wait_for_start(status: Cell, control: Cell, pid: u64) -> Result<(u64, u64, u64), ()> {
    let deadline = time().saturating_add(WAIT_TICKS);
    loop {
        let (status_version, status_word) = status.read().map_err(|_| ())?;
        let phase = program::client_service_phase(status_word);
        let generation = program::client_service_generation(status_word);
        if program::client_service_value(status_word) == pid {
            let (control_version, control_word) = control.read().map_err(|_| ())?;
            let expected_generation = if phase == program::CLIENT_SERVICE_ACTIVE_STALE {
                generation.checked_sub(1).ok_or(())?
            } else {
                generation
            };
            if program::client_service_phase(control_word) == phase
                && program::client_service_generation(control_word) == expected_generation
            {
                return Ok((
                    phase,
                    generation,
                    program::client_service_value(control_word),
                ));
            }
            let now = time();
            if now >= deadline
                || control
                    .wait_change_timeout(control_version, deadline - now)
                    .is_err()
            {
                return Err(());
            }
            continue;
        }
        let now = time();
        if now >= deadline
            || status
                .wait_change_timeout(status_version, deadline - now)
                .is_err()
        {
            return Err(());
        }
    }
}

fn main(start: MultiStart<'_>) -> i32 {
    let [status_raw, control_raw, state_raw] = start.handles else {
        return 110;
    };
    // Every instance gets read-only status and request/control handles, plus
    // read-write authority to the stable service-state cell. Process handles
    // remain solely in init.
    let status = Cell::from_raw(*status_raw);
    let control = Cell::from_raw(*control_raw);
    let state = Cell::from_raw(*state_raw);
    if status.transition(0, 0) != Err(Error::Rights)
        || control.transition(0, 0) != Err(Error::Rights)
    {
        return 109;
    }
    let pid = getpid();
    let Ok((phase, generation, request)) = wait_for_start(status, control, pid) else {
        return 111;
    };
    let _ = absd_user::cprintln!(
        start.console,
        "CLIENT SERVICE START generation={} pid={} request={}",
        generation,
        pid,
        request
    );

    match phase {
        program::CLIENT_SERVICE_ACTIVE_FAULT => intentional_fault(),
        program::CLIENT_SERVICE_ACTIVE_RETRY => {
            let Ok((version, prior)) = state.read() else {
                return 112;
            };
            if prior == request || state.transition(version, request) != Ok(version + 1) {
                return 113;
            }
            let deadline = time().saturating_add(WAIT_TICKS);
            loop {
                let Ok((seen, word)) = status.read() else {
                    return 114;
                };
                if program::client_service_phase(word) == program::CLIENT_SERVICE_STOP
                    && program::client_service_generation(word) == generation
                    && program::client_service_value(word) == pid
                {
                    return 0;
                }
                let now = time();
                if now >= deadline {
                    return 115;
                }
                if status.wait_change_timeout(seen, deadline - now).is_err() {
                    return 116;
                }
            }
        }
        program::CLIENT_SERVICE_ACTIVE_STALE => {
            let Ok((version, value)) = state.read() else {
                return 118;
            };
            // The control event intentionally names the prior generation.
            // Generation is not a fencing token, but this protocol refuses
            // obsolete work before invoking any state transition at all.
            if generation < 2
                || request != program::CLIENT_SERVICE_REQUEST_A
                || state.read() != Ok((version, value))
            {
                return 119;
            }
            42
        }
        program::CLIENT_SERVICE_ACTIVE_APPLY_FAULT => {
            let Ok((version, prior)) = state.read() else {
                return 121;
            };
            if prior == request || state.transition(version, request) != Ok(version + 1) {
                return 122;
            }
            intentional_fault()
        }
        program::CLIENT_SERVICE_ACTIVE_RECONCILE | program::CLIENT_SERVICE_ACTIVE_CAPACITY => {
            let Ok((version, value)) = state.read() else {
                return 123;
            };
            if value != request
                || version == 0
                || state.transition(version - 1, request) != Err(Error::Stale)
                || state.read() != Ok((version, request))
            {
                return 124;
            }
            0
        }
        program::CLIENT_SERVICE_ACTIVE_NORMAL | program::CLIENT_SERVICE_ACTIVE_HEADROOM => {
            let Ok((version, prior)) = state.read() else {
                return 125;
            };
            if prior == request || state.transition(version, request) != Ok(version + 1) {
                return 126;
            }
            0
        }
        _ => 127,
    }
}
