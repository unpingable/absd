//! Indices into the kernel's embedded program catalog, the only way to name
//! an executable until there is a filesystem. `src/user_program.rs` in the
//! kernel asserts that its catalog matches this order.

/// Startup mode passed in `Start.arg` to the kernel-created init process.
pub const INIT_MODE_SUITE: u64 = 0;
pub const INIT_MODE_SHELL: u64 = 1;
pub const INIT_MODE_FUZZ: u64 = 2;
pub const INIT_MODE_EXTERNAL: u64 = 3;
/// Run the generic external workload with host bytes arriving after boot.
pub const INIT_MODE_EXTERNAL_LIVE: u64 = 4;
/// Run the embedded block probe against the attached storage device.
pub const INIT_MODE_BLOCK_PROBE: u64 = 5;
/// Run the external workload with the block device and a step cell.
pub const INIT_MODE_DURABLE: u64 = 6;
/// Run the embedded NIC probe with the NIC (kernel `net-probe` boot).
pub const INIT_MODE_NET_PROBE: u64 = 7;
/// A durable boot with a file server (boot option `fsd`): init starts the
/// catalog's file server with the read-write block handle and the server
/// ends of the channels it mints, then the worker with the client ends and
/// no block handle (docs/PROCESS-STARTUP.md, "File server").
pub const INIT_MODE_DURABLE_FSD: u64 = 8;
/// A served boot (boot options `fsd served`): the `fsd` composition whose
/// worker runs until it ends itself, with no worker deadline. Its exit
/// status asks init for the end of the boot: 0 halts the machine,
/// [`SERVED_WORKER_RESTART_STATUS`] restarts it; anything else fails the
/// boot. Qualification boots keep the worker deadline.
pub const INIT_MODE_SERVED_FSD: u64 = 9;
/// Run the hostile-userspace qualification battery (kernel `hostile` boot;
/// docs/HOSTILE-USERSPACE.md).
pub const INIT_MODE_HOSTILE: u64 = 10;
/// Opt-in scheduler experiment; no ambient RT admission.
pub const INIT_MODE_RT_TEST: u64 = 11;
pub const INIT_MODE_RT_CLASS: u64 = 12;
/// Controlled two-CPU kernel-only stop/reclaim qualification.
pub const INIT_MODE_SMP_LIFECYCLE: u64 = 13;
/// The BSP spawner is stopped before its Created child is published.
pub const INIT_MODE_SMP_CREATED_STOP: u64 = 14;
/// Qualification-only served boot whose file server receives one fixed
/// failure-control argument. Ordinary served boots use mode 9.
pub const INIT_MODE_SERVED_FSD_EXIT_TEST: u64 = 15;
/// Qualification of the machine recover right in an ordinary (not served)
/// boot: init hands a recover-only duplicate to a child that is not PID 1,
/// and the child's `machine_recover` resets the machine.
pub const INIT_MODE_MACHINE_RECOVER_TEST: u64 = 16;
/// FPU/MXCSR state-isolation qualification boot (docs/HOSTILE-USERSPACE.md).
pub const INIT_MODE_FPU_TEST: u64 = 17;
/// Qualification-only served boot whose file server receives the fixed
/// hang-control argument (`--qualification-hang-on-notice`): on the
/// notice it spins in user mode and never beats its liveness cell, so only
/// init's liveness judgment can end the generation
/// (docs/service-lifecycle-20261008/LIVENESS.md). Ordinary served boots
/// use mode 9.
pub const INIT_MODE_SERVED_FSD_HANG_TEST: u64 = 18;
/// The durable modes carry the boot's step number above the mode byte.
pub const INIT_MODE_MASK: u64 = 0xff;
pub const INIT_STEP_SHIFT: u32 = 8;

pub const fn init_arg(mode: u64, step: u64) -> u64 {
    (mode & INIT_MODE_MASK) | (step << INIT_STEP_SHIFT)
}
pub const fn init_mode(arg: u64) -> u64 {
    arg & INIT_MODE_MASK
}
pub const fn init_step(arg: u64) -> u64 {
    arg >> INIT_STEP_SHIFT
}

/// A durable worker that exits with `DURABLE_WORKER_ABORT_STATUS` is replaced
/// by init with the same step word plus one in the replacement digit
/// (`DURABLE_REPLACEMENT_UNIT`), so the replacement knows it is resuming and
/// what it is resuming, but takes every fact about progress from the
/// device, never from init's memory of the predecessor. Everything else about
/// the step word belongs to the workload.
pub const DURABLE_REPLACEMENT_UNIT: u64 = 1_000_000_000_000;
pub const DURABLE_WORKER_ABORT_STATUS: i32 = 97;
/// Bound on worker generations init will start in one durable boot.
pub const DURABLE_MAX_GENERATIONS: u64 = 4;

pub const fn durable_replacement_step(step: u64) -> u64 {
    step + DURABLE_REPLACEMENT_UNIT
}

/// The exit status with which a served boot's worker asks init to restart
/// the machine after the orderly shutdown (0 asks for a halt). Init holds
/// the restart right; the worker holds none.
pub const SERVED_WORKER_RESTART_STATUS: i32 = 98;

/// The `machine_stop` code with which a served boot's init ends a requested
/// halt that left a live adopted process (QEMU status 71).
pub const SERVED_UNREAPED_STOP_CODE: u64 = 17;
/// The `machine_stop` code with which a served boot's init ends a requested
/// halt whose file server did not stop cleanly (QEMU status 75).
pub const SERVED_FILE_SERVER_STOP_CODE: u64 = 18;

/// The `machine_stop` code with which a served boot's init ends a requested
/// halt whose worker stream failed after the request was reaped (an output
/// pipe still held, a console write or close error; QEMU status 79).
pub const SERVED_WORKER_STREAM_STOP_CODE: u64 = 19;
/// A served boot's recovery budget: how many automatic recovery resets
/// (whole-machine resets after a post-ready failure) may follow one
/// another without an orderly end between them. A generation that starts
/// with this many consecutive failed generations behind it is the last
/// permitted one: its post-ready failure stops the machine
/// (docs/service-lifecycle-20261008/RECOVERY-BUDGET.md).
pub const SERVED_RECOVERY_BUDGET: u64 = 3;
/// The `machine_stop` code of that terminal stop (QEMU status 83).
pub const SERVED_RECOVERY_BUDGET_STOP_CODE: u64 = 20;
/// The `machine_stop` code when a post-ready failure finds no recovery
/// streak was advertised before readiness (`SSH RECOVERY streak=`): the
/// count is unverifiable, so nothing resets (QEMU status 87).
pub const SERVED_RECOVERY_UNKNOWN_STOP_CODE: u64 = 21;

/// How long a served service's liveness cell may stay unchanged after
/// readiness before init treats the service as unresponsive: about 60 s
/// of guest ticks (docs/service-lifecycle-20261008/LIVENESS.md). The
/// services transition their cell once per loop pass, and a pass is
/// bounded well under this; the bound is deliberately coarse so that a
/// slow but live service never spends the recovery budget.
pub const SERVED_LIVENESS_TICKS: u64 = 60_000;
/// The tick-jump rule: if more than this passed between two of init's own
/// observations, init itself did not run for that long (the whole guest
/// was stopped, or every process waited inside the kernel on a device),
/// so nothing about the services can be concluded from that interval.
/// Both witnesses are rebased to the observation and the interval is not
/// judged. Init observes every `ORPHAN_REAP_TICKS` (100), so an honest
/// gap this large is never the scheduler's doing.
pub const SERVED_LIVENESS_GAP_TICKS: u64 = 2_000;

/// A served boot's two essential services, as init's liveness judgment
/// names them.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ServedComponent {
    FileServer,
    Worker,
}

impl ServedComponent {
    /// The component word on init's console lines.
    pub const fn name(self) -> &'static str {
        match self {
            Self::FileServer => "fsd",
            Self::Worker => "sshd",
        }
    }

    /// The reason `recover_served` prints when the component stopped
    /// beating: distinct from the exit reasons, so a stall is never read
    /// as an exit.
    pub const fn unresponsive_reason(self) -> &'static str {
        match self {
            Self::FileServer => "file server unresponsive",
            Self::Worker => "served worker unresponsive",
        }
    }
}

/// One observation's verdict.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum LivenessVerdict {
    /// Both cells moved within the bound, or the judgment just started.
    Live,
    /// Init itself did not run for `ticks`: the interval is not judged
    /// and both witnesses restart at this observation.
    Gap { ticks: u64 },
    /// `component` has not moved its cell for `idle_ticks` (at least the
    /// bound). The file server is named first when both have gone quiet:
    /// sshd blocks in its untimed exchange with a file server that stopped
    /// serving, so an unresponsive file server always takes sshd with it,
    /// and sshd's last beat precedes the file server's by up to one pass.
    /// sshd is therefore named only while the file server is demonstrably
    /// live (its cell moved within half the bound); otherwise the verdict
    /// waits for the file server to cross the bound.
    Stale {
        component: ServedComponent,
        idle_ticks: u64,
        sshd_idle_ticks: u64,
        fsd_idle_ticks: u64,
    },
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct LivenessWitness {
    /// The cell version last seen.
    version: u64,
    /// The observation tick at which that version was first seen.
    since: u64,
}

impl LivenessWitness {
    const fn new(version: u64, now: u64) -> Self {
        Self {
            version,
            since: now,
        }
    }

    fn observe(&mut self, version: u64, now: u64) -> u64 {
        if version != self.version {
            self.version = version;
            self.since = now;
        }
        now.saturating_sub(self.since)
    }
}

/// Init's liveness judgment over the two served services' heartbeat
/// cells: pure policy over (tick, sshd cell version, fsd cell version)
/// observations, so it is host-testable; init supplies the readings.
/// Judgment begins at readiness (`start`), never before: a generation that
/// does not reach readiness is the existing pre-ready refusal's business.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ServedLiveness {
    started: bool,
    last_pass: u64,
    sshd: LivenessWitness,
    fsd: LivenessWitness,
}

impl ServedLiveness {
    pub const fn new() -> Self {
        Self {
            started: false,
            last_pass: 0,
            sshd: LivenessWitness::new(0, 0),
            fsd: LivenessWitness::new(0, 0),
        }
    }

    /// Whether `start` ran.
    pub const fn started(&self) -> bool {
        self.started
    }

    /// Begins judging at `now` with both cells read as fresh: the first
    /// bound counts from readiness, not from spawn.
    pub fn start(&mut self, now: u64, sshd_version: u64, fsd_version: u64) {
        self.started = true;
        self.last_pass = now;
        self.sshd = LivenessWitness::new(sshd_version, now);
        self.fsd = LivenessWitness::new(fsd_version, now);
    }

    /// One observation per reap pass. Returns `Live` before `start`.
    pub fn observe(&mut self, now: u64, sshd_version: u64, fsd_version: u64) -> LivenessVerdict {
        if !self.started {
            return LivenessVerdict::Live;
        }
        let gap = now.saturating_sub(self.last_pass);
        self.last_pass = now;
        let sshd_idle = self.sshd.observe(sshd_version, now);
        let fsd_idle = self.fsd.observe(fsd_version, now);
        if gap > SERVED_LIVENESS_GAP_TICKS {
            self.sshd.since = now;
            self.fsd.since = now;
            return LivenessVerdict::Gap { ticks: gap };
        }
        let component = if fsd_idle >= SERVED_LIVENESS_TICKS {
            ServedComponent::FileServer
        } else if sshd_idle >= SERVED_LIVENESS_TICKS && fsd_idle < SERVED_LIVENESS_TICKS / 2 {
            ServedComponent::Worker
        } else {
            // Either both are within the bound, or sshd crossed it while
            // the file server has also been quiet for half of it: that is
            // the file server's stall seen through sshd, and the file
            // server is named when its own cell crosses the bound.
            return LivenessVerdict::Live;
        };
        LivenessVerdict::Stale {
            component,
            idle_ticks: match component {
                ServedComponent::FileServer => fsd_idle,
                ServedComponent::Worker => sshd_idle,
            },
            sshd_idle_ticks: sshd_idle,
            fsd_idle_ticks: fsd_idle,
        }
    }
}

impl Default for ServedLiveness {
    fn default() -> Self {
        Self::new()
    }
}

/// Where a served boot's init routes a failure (an `Err` reaching main).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ServedFailureRoute {
    /// `end_served` already decided the end; the boot just fails.
    Decided,
    /// The worker's exit 0 or 98 was reaped: finish the orderly end with
    /// [`ServedEndFailure::WorkerStream`].
    OrderlyEnd,
    /// No request was reaped: a fault during service.
    FaultRecovery,
}

pub const fn served_failure_route(end_decided: bool, request_recorded: bool) -> ServedFailureRoute {
    if end_decided {
        ServedFailureRoute::Decided
    } else if request_recorded {
        ServedFailureRoute::OrderlyEnd
    } else {
        ServedFailureRoute::FaultRecovery
    }
}

/// Why a served boot's orderly end (the worker asked for a halt or a
/// restart) could not finish as asked. docs/PROCESS-STARTUP.md, "Served
/// boot and orderly shutdown", lists each outcome and marker.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ServedEndFailure {
    /// A process the sessions left was still alive after the drain bound.
    Unreaped,
    /// Waiting for the sessions' orphans failed other than by timing out.
    DrainWait,
    /// The file server exited with a non-zero status or faulted.
    FileServerStatus,
    /// The file server did not stop within its bound.
    FileServerTimeout,
    /// Waiting for the file server failed other than by timing out.
    FileServerWait,
    /// After the worker's request was reaped, init's handling of its
    /// stream failed (`ServedFailureRoute::OrderlyEnd`).
    WorkerStream,
}

/// What init does with a failed orderly end.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ServedEscalation {
    /// `machine_stop` with this code: the machine does not come back.
    Stop(u64),
    /// `machine_recover`: the whole-machine reset, which satisfies a
    /// requested restart without the end-of-boot accounting.
    RecoveryReset,
}

impl ServedEscalation {
    pub const fn name(self) -> &'static str {
        match self {
            Self::Stop(_) => "stop",
            Self::RecoveryReset => "recovery_reset",
        }
    }
}

impl ServedEndFailure {
    pub const fn reason(self) -> &'static str {
        match self {
            Self::Unreaped => "unreaped",
            Self::DrainWait => "drain_wait",
            Self::FileServerStatus => "file_server_status",
            Self::FileServerTimeout => "file_server_timeout",
            Self::FileServerWait => "file_server_wait",
            Self::WorkerStream => "worker_stream",
        }
    }

    /// The escalation code: the stop code of a requested halt, and the
    /// code the marker reports for a requested restart.
    pub const fn code(self) -> u64 {
        match self {
            Self::Unreaped | Self::DrainWait => SERVED_UNREAPED_STOP_CODE,
            Self::FileServerStatus | Self::FileServerTimeout | Self::FileServerWait => {
                SERVED_FILE_SERVER_STOP_CODE
            }
            Self::WorkerStream => SERVED_WORKER_STREAM_STOP_CODE,
        }
    }

    /// The operator's intent decides: a requested halt never resets the
    /// machine; a requested restart takes the recovery reset, but only once
    /// the generation was ready (the same rule as the fault path's pre-ready
    /// refusal), and stops before that.
    pub const fn escalation(self, restart: bool, ready: bool) -> ServedEscalation {
        if restart && ready {
            ServedEscalation::RecoveryReset
        } else {
            ServedEscalation::Stop(self.code())
        }
    }
}

/// What init does with a post-ready failure, given the recovery streak the
/// generation advertised before readiness (`None`: it never did).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RecoveryDecision {
    /// Under budget: the whole-machine recovery reset.
    Reset,
    /// `machine_stop` with the code; the reason names why.
    Stop { code: u64, reason: &'static str },
}

pub const fn recovery_decision(streak: Option<u64>) -> RecoveryDecision {
    match streak {
        None => RecoveryDecision::Stop {
            code: SERVED_RECOVERY_UNKNOWN_STOP_CODE,
            reason: "recovery_budget_unknown",
        },
        Some(streak) if streak >= SERVED_RECOVERY_BUDGET => RecoveryDecision::Stop {
            code: SERVED_RECOVERY_BUDGET_STOP_CODE,
            reason: "recovery_budget_exhausted",
        },
        Some(_) => RecoveryDecision::Reset,
    }
}

/// Streaming recognition of sshd's complete listener record. Init uses this
/// as the post-startup recovery gate; diagnostics containing the words alone
/// must never authorize an automatic machine reset, and neither does a
/// listener with `authorized_keys=0`. The record is sshd's self-report.
pub struct ServedReadyProbe {
    line: [u8; 96],
    length: usize,
    overflow: bool,
    /// The recovery streak sshd advertised (`SSH RECOVERY streak=`),
    /// once seen; it precedes the listener record.
    streak: Option<u64>,
}

impl ServedReadyProbe {
    pub const fn new() -> Self {
        Self {
            line: [0; 96],
            length: 0,
            overflow: false,
            streak: None,
        }
    }

    /// The streak advertised so far, if any.
    pub const fn streak(&self) -> Option<u64> {
        self.streak
    }

    pub fn push(&mut self, bytes: &[u8]) -> bool {
        for &byte in bytes {
            if byte == b'\n' {
                if !self.overflow
                    && let Some(streak) = Self::streak_line(&self.line[..self.length])
                {
                    self.streak = Some(streak);
                }
                let ready = !self.overflow && Self::ready_line(&self.line[..self.length]);
                self.length = 0;
                self.overflow = false;
                if ready {
                    return true;
                }
            } else if self.length < self.line.len() && !self.overflow {
                self.line[self.length] = byte;
                self.length += 1;
            } else {
                self.overflow = true;
            }
        }
        false
    }

    fn streak_line(line: &[u8]) -> Option<u64> {
        let digits = line.strip_prefix(b"SSH RECOVERY streak=")?;
        if digits.is_empty() || digits.len() > 19 || !digits.iter().all(u8::is_ascii_digit) {
            return None;
        }
        Some(
            digits
                .iter()
                .fold(0u64, |acc, &d| acc * 10 + u64::from(d - b'0')),
        )
    }

    fn ready_line(line: &[u8]) -> bool {
        const PREFIX: &[u8] = b"SSH LISTENING port=";
        const FIELD: &[u8] = b" authorized_keys=";
        const SOURCE: &[u8] = b" preauth_per_source=";
        let Some(rest) = line.strip_prefix(PREFIX) else {
            return false;
        };
        let Some(separator) = rest.windows(FIELD.len()).position(|window| window == FIELD) else {
            return false;
        };
        let port = &rest[..separator];
        let tail = &rest[separator + FIELD.len()..];
        let Some(source_at) = tail
            .windows(SOURCE.len())
            .position(|window| window == SOURCE)
        else {
            return false;
        };
        let keys = &tail[..source_at];
        let source = &tail[source_at + SOURCE.len()..];
        !port.is_empty()
            && port.iter().all(u8::is_ascii_digit)
            && !keys.is_empty()
            && keys.iter().all(u8::is_ascii_digit)
            // A generation nobody can log into is not ready for an
            // automatic reset.
            && keys.iter().any(|digit| *digit != b'0')
            && !source.is_empty()
            && source.iter().all(u8::is_ascii_digit)
    }
}

impl Default for ServedReadyProbe {
    fn default() -> Self {
        Self::new()
    }
}

/// Startup-word layout for the bounded supervision worker experiment.
pub const SUPERVISED_MODE_SHIFT: u32 = 56;
pub const SUPERVISED_GENERATION_MASK: u64 = (1u64 << SUPERVISED_MODE_SHIFT) - 1;
pub const SUPERVISED_MODE_TRANSITION: u64 = 0;
pub const SUPERVISED_MODE_GRACEFUL_STOP: u64 = 1;
pub const SUPERVISED_MODE_STUCK: u64 = 2;
pub const SUPERVISED_STOP_VALUE: u64 = 0x5354_4f50;

pub const fn supervised_arg(mode: u64, generation: u64) -> u64 {
    (mode << SUPERVISED_MODE_SHIFT) | (generation & SUPERVISED_GENERATION_MASK)
}

/// Startup-word layout for the request/reconciliation recovery worker.
pub const RECOVERY_MODE_SHIFT: u32 = 56;
pub const RECOVERY_GENERATION_SHIFT: u32 = 32;
pub const RECOVERY_GENERATION_MASK: u64 = 0x00ff_ffff;
pub const RECOVERY_REQUEST_MASK: u64 = 0xffff_ffff;
pub const RECOVERY_MODE_FAULT_BEFORE: u64 = 0;
pub const RECOVERY_MODE_APPLY_THEN_FAULT: u64 = 1;
pub const RECOVERY_MODE_RECONCILE: u64 = 2;
pub const RECOVERY_MODE_NORMAL: u64 = 3;

pub const fn recovery_arg(mode: u64, generation: u64, request: u64) -> u64 {
    (mode << RECOVERY_MODE_SHIFT)
        | ((generation & RECOVERY_GENERATION_MASK) << RECOVERY_GENERATION_SHIFT)
        | (request & RECOVERY_REQUEST_MASK)
}

/// Userspace-only client/service experiment cell protocol. These are cell
/// values, not kernel ABI state: generation is diagnostic metadata while
/// conditional cell transitions remain the authority for applying requests.
pub const CLIENT_SERVICE_PHASE_SHIFT: u32 = 56;
pub const CLIENT_SERVICE_GENERATION_SHIFT: u32 = 32;
pub const CLIENT_SERVICE_GENERATION_MASK: u64 = 0x00ff_ffff;
pub const CLIENT_SERVICE_VALUE_MASK: u64 = 0xffff_ffff;

pub const CLIENT_SERVICE_COMMAND_FAULT: u64 = 1;
pub const CLIENT_SERVICE_ACTIVE_FAULT: u64 = 2;
pub const CLIENT_SERVICE_UNAVAILABLE: u64 = 3;
pub const CLIENT_SERVICE_COMMAND_RETRY: u64 = 4;
pub const CLIENT_SERVICE_ACTIVE_RETRY: u64 = 5;
pub const CLIENT_SERVICE_COMPLETE_RETRY: u64 = 6;
pub const CLIENT_SERVICE_STOP: u64 = 7;
pub const CLIENT_SERVICE_COMMAND_STALE: u64 = 8;
pub const CLIENT_SERVICE_ACTIVE_STALE: u64 = 9;
pub const CLIENT_SERVICE_STALE_REFUSED: u64 = 10;
pub const CLIENT_SERVICE_COMMAND_APPLY_FAULT: u64 = 11;
pub const CLIENT_SERVICE_ACTIVE_APPLY_FAULT: u64 = 12;
pub const CLIENT_SERVICE_COMMAND_RECONCILE: u64 = 13;
pub const CLIENT_SERVICE_ACTIVE_RECONCILE: u64 = 14;
pub const CLIENT_SERVICE_COMPLETE_RECONCILE: u64 = 15;
pub const CLIENT_SERVICE_COMMAND_NORMAL: u64 = 16;
pub const CLIENT_SERVICE_ACTIVE_NORMAL: u64 = 17;
pub const CLIENT_SERVICE_COMPLETE_NORMAL: u64 = 18;
pub const CLIENT_SERVICE_PENDING_CAPACITY: u64 = 19;
pub const CLIENT_SERVICE_ACTIVE_CAPACITY: u64 = 20;
pub const CLIENT_SERVICE_COMPLETE_CAPACITY: u64 = 21;
pub const CLIENT_SERVICE_PENDING_HEADROOM: u64 = 22;
pub const CLIENT_SERVICE_ACTIVE_HEADROOM: u64 = 23;
pub const CLIENT_SERVICE_COMPLETE_HEADROOM: u64 = 24;
pub const CLIENT_SERVICE_FINISH: u64 = 25;

pub const CLIENT_SERVICE_REQUEST_A: u64 = 0x101;
pub const CLIENT_SERVICE_REQUEST_B: u64 = 0x202;
pub const CLIENT_SERVICE_REQUEST_C: u64 = 0x303;
pub const CLIENT_SERVICE_REQUEST_D: u64 = 0x404;
pub const CLIENT_SERVICE_REQUEST_E: u64 = 0x505;

pub const fn client_service_word(phase: u64, generation: u64, value: u64) -> u64 {
    (phase << CLIENT_SERVICE_PHASE_SHIFT)
        | ((generation & CLIENT_SERVICE_GENERATION_MASK) << CLIENT_SERVICE_GENERATION_SHIFT)
        | (value & CLIENT_SERVICE_VALUE_MASK)
}

pub const fn client_service_phase(word: u64) -> u64 {
    word >> CLIENT_SERVICE_PHASE_SHIFT
}

pub const fn client_service_generation(word: u64) -> u64 {
    (word >> CLIENT_SERVICE_GENERATION_SHIFT) & CLIENT_SERVICE_GENERATION_MASK
}

pub const fn client_service_value(word: u64) -> u64 {
    word & CLIENT_SERVICE_VALUE_MASK
}

pub const INIT: u64 = 0;
pub const HELLO_A: u64 = 1;
pub const HELLO_B: u64 = 2;
pub const EXIT7: u64 = 3;
pub const FAULT: u64 = 4;
pub const FPU: u64 = 5;
pub const TRAP: u64 = 6;
pub const PRIVILEGED: u64 = 7;
pub const HEAP: u64 = 8;
pub const UNMAPPED: u64 = 9;
pub const OVERFLOW: u64 = 10;
pub const CELL: u64 = 11;
pub const SHARED: u64 = 12;
pub const READONLY: u64 = 13;
pub const WATCHER: u64 = 14;
pub const PIPER: u64 = 15;
pub const SLEEPER: u64 = 16;
pub const SHELL: u64 = 17;
pub const FUZZ: u64 = 18;
pub const MULTI_HANDLE: u64 = 19;
pub const STACK_GROW: u64 = 20;
pub const STACK_JUMP: u64 = 21;
pub const ORPHANER: u64 = 22;
pub const SUPERVISED_WORKER: u64 = 23;
pub const RECOVERY_WORKER: u64 = 24;
pub const SERVICE_CLIENT: u64 = 25;
pub const CLIENT_SERVICE_WORKER: u64 = 26;
pub const ALLOC_PROBE: u64 = 27;
pub const ISOLATION: u64 = 28;
pub const INPUT_STREAM: u64 = 29;
pub const EXTERNAL_WORKLOAD: u64 = 30;
pub const BLOCK_PROBE: u64 = 31;
/// A second external program a durable boot runs after its worker exits,
/// holding only a read-only duplicate of the block handle.
pub const EXTERNAL_READER: u64 = 32;
/// Programs init may start on a durable worker's request, as its broker
/// (docs/BROKER.md). An opt-in build replaces their images; by default they
/// hold the `broker-child` test program.
pub const OWNER_1: u64 = 33;
pub const OWNER_2: u64 = 34;
pub const OWNER_3: u64 = 35;
pub const OWNER_4: u64 = 36;
pub const OWNERS: [u64; 4] = [OWNER_1, OWNER_2, OWNER_3, OWNER_4];
/// The program index `info` reports for a process `spawn_image` started
/// from an image in its parent's memory rather than from the catalog.
pub const IMAGE: u64 = 0xffff_ffff;
/// The NIC qualification program of a `net-probe` boot (docs/NETWORK.md).
pub const NIC_PROBE: u64 = 37;
/// The file server of an `fsd` durable boot (docs/PROCESS-STARTUP.md). An
/// opt-in build supplies its image; by default the slot holds the default
/// external workload, and init refuses an `fsd` boot without a real one.
pub const FILE_SERVER: u64 = 38;
/// Tries to recover and stop the machine with no or a narrowed machine
/// handle; init's suite checks every attempt is refused, and the
/// `machine-recover-test` boot hands it a recover-only handle.
pub const MACHINE_PROBE: u64 = 39;
/// Init's hostile qualification boot spawns this with a case selector: a
/// non-fatal syscall/pointer abuse battery, then one hostile act per case
/// whose exact exception the kernel must report (docs/HOSTILE-USERSPACE.md).
pub const HOSTILE_PROBE: u64 = 40;
pub const RT_PROBE: u64 = 41;
/// The FPU/MXCSR state-isolation probe of an `fpu-test` boot: its start
/// argument selects the isolation task, the #XM fault case, or a witness
/// (docs/HOSTILE-USERSPACE.md).
pub const FPU_MXCSR: u64 = 42;
/// Client channels init mints for an `fsd` boot besides the control
/// channel: two pipes each, so the control channel and these take
/// `2 * (1 + FILE_SERVER_SLOTS)` of the kernel's 48 pipes for the boot.
pub const FILE_SERVER_SLOTS: usize = 10;
pub const INPUT_STREAM_BYTES: usize = 1245;
pub const INPUT_STREAM_DIGEST: u32 = 0xfaef_2b56;

/// Deterministic application-neutral input used by the stream probe.
pub const fn input_stream_byte(index: usize) -> u8 {
    (index
        .wrapping_mul(73)
        .wrapping_add((index / 4).wrapping_mul(19))
        .wrapping_add(0x5a)
        & 0xff) as u8
}

/// Private qualification fixture; AP placement is available only in the
/// separately compiled and explicitly selected SMP user test boot.
pub const SMP_USER: u64 = 43;
pub const NAMES: [&str; 44] = [
    "init",
    "hello-a",
    "hello-b",
    "exit7",
    "fault",
    "fpu",
    "trap",
    "privileged",
    "heap",
    "unmapped",
    "overflow",
    "cell",
    "shared",
    "readonly",
    "watcher",
    "piper",
    "sleeper",
    "shell",
    "fuzz",
    "multi-handle",
    "stack-grow",
    "stack-jump",
    "orphaner",
    "supervised-worker",
    "recovery-worker",
    "service-client",
    "client-service-worker",
    "alloc-probe",
    "isolation",
    "input-stream",
    "external-workload",
    "block-probe",
    "external-reader",
    "owner-1",
    "owner-2",
    "owner-3",
    "owner-4",
    "nic-probe",
    "file-server",
    "machine-probe",
    "hostile-probe",
    "rt-probe",
    "fpu-mxcsr",
    "smp-user",
];

/// Legacy-entry programs safe for the fuzz process to start and collect.
/// Programs with incompatible entry state or required explicit authority stay
/// out of this deliberately explicit list.
pub const FUZZ_LEGACY_PROGRAMS: [u64; 20] = [
    HELLO_A, HELLO_B, EXIT7, FAULT, FPU, TRAP, PRIVILEGED, HEAP, UNMAPPED, OVERFLOW, CELL, SHARED,
    READONLY, WATCHER, PIPER, SLEEPER, SHELL, FUZZ, STACK_GROW, STACK_JUMP,
];

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn served_ready_requires_complete_current_listener_record() {
        let marker = b"SSH LISTENING port=2222 authorized_keys=1 preauth_per_source=2\n";
        for split in 0..=marker.len() {
            let mut probe = ServedReadyProbe::new();
            let first = probe.push(&marker[..split]);
            let second = probe.push(&marker[split..]);
            assert_eq!(first as u8 + second as u8, 1, "split={split}");
        }
        let mut probe = ServedReadyProbe::new();
        assert!(
            !probe.push(
                b"FSD FAILED: SSH LISTENING port=2222 authorized_keys=1 preauth_per_source=2\n"
            )
        );
        assert!(!probe.push(b"SSH LISTENING port=2222 authorized_keys=1\n"));
        assert!(
            !probe
                .push(b"SSH LISTENING port=2222 authorized_keys=1 preauth_per_source=2 extra=1\n")
        );
        assert!(!probe.push(b"SSH LISTENING port=2222 authorized_keys=1 preauth_per_source=2"));
        assert!(probe.push(b"\n"));
    }

    #[test]
    fn served_ready_refuses_a_listener_nobody_can_log_into() {
        for keys in [&b"0"[..], b"00"] {
            let mut line = [0u8; 80];
            let mut length = 0;
            for part in [
                &b"SSH LISTENING port=2222 authorized_keys="[..],
                keys,
                b" preauth_per_source=2\n",
            ] {
                line[length..length + part.len()].copy_from_slice(part);
                length += part.len();
            }
            assert!(!ServedReadyProbe::new().push(&line[..length]));
        }
        assert!(
            ServedReadyProbe::new()
                .push(b"SSH LISTENING port=2222 authorized_keys=01 preauth_per_source=2\n")
        );
    }

    #[test]
    fn served_end_escalation_never_restarts_a_requested_halt() {
        let all = [
            ServedEndFailure::Unreaped,
            ServedEndFailure::DrainWait,
            ServedEndFailure::FileServerStatus,
            ServedEndFailure::FileServerTimeout,
            ServedEndFailure::FileServerWait,
            ServedEndFailure::WorkerStream,
        ];
        for failure in all {
            for ready in [false, true] {
                assert_eq!(
                    failure.escalation(false, ready),
                    ServedEscalation::Stop(failure.code()),
                    "{failure:?}"
                );
            }
            assert_eq!(
                failure.escalation(true, true),
                ServedEscalation::RecoveryReset
            );
            // Before readiness no automatic reset: a restart stops instead.
            assert_eq!(
                failure.escalation(true, false),
                ServedEscalation::Stop(failure.code()),
                "{failure:?}"
            );
            assert!(
                (crate::syscall::STOP_CODE_MIN..=crate::syscall::STOP_CODE_MAX)
                    .contains(&failure.code())
            );
        }
        assert_eq!(SERVED_UNREAPED_STOP_CODE, 17);
        assert_eq!(SERVED_FILE_SERVER_STOP_CODE, 18);
        assert_eq!(ServedEndFailure::Unreaped.code(), 17);
        assert_eq!(ServedEndFailure::DrainWait.code(), 17);
        assert_eq!(ServedEndFailure::FileServerStatus.code(), 18);
        assert_eq!(ServedEndFailure::FileServerTimeout.code(), 18);
        assert_eq!(ServedEndFailure::FileServerWait.code(), 18);
        assert_eq!(SERVED_WORKER_STREAM_STOP_CODE, 19);
        assert_eq!(ServedEndFailure::WorkerStream.code(), 19);
        let reasons = all.map(ServedEndFailure::reason);
        assert_eq!(
            reasons,
            [
                "unreaped",
                "drain_wait",
                "file_server_status",
                "file_server_timeout",
                "file_server_wait",
                "worker_stream"
            ]
        );
        assert_eq!(ServedEscalation::Stop(17).name(), "stop");
        assert_eq!(ServedEscalation::RecoveryReset.name(), "recovery_reset");
    }

    #[test]
    fn served_failure_after_a_request_finishes_the_orderly_end() {
        // A failure after init reaped the worker's exit 0 or 98 is part of
        // the orderly end, never a fault during service.
        assert_eq!(
            served_failure_route(false, true),
            ServedFailureRoute::OrderlyEnd
        );
        assert_eq!(
            served_failure_route(false, false),
            ServedFailureRoute::FaultRecovery
        );
        for request in [false, true] {
            assert_eq!(
                served_failure_route(true, request),
                ServedFailureRoute::Decided
            );
        }
    }

    #[test]
    fn supervised_startup_word_separates_mode_and_generation() {
        let generation = SUPERVISED_GENERATION_MASK - 1;
        let argument = supervised_arg(SUPERVISED_MODE_STUCK, generation);
        assert_eq!(argument >> SUPERVISED_MODE_SHIFT, SUPERVISED_MODE_STUCK);
        assert_eq!(argument & SUPERVISED_GENERATION_MASK, generation);
    }

    #[test]
    fn three_recovery_resets_then_the_fourth_failure_stops() {
        assert_eq!(SERVED_RECOVERY_BUDGET, 3);
        for streak in 0..3 {
            assert_eq!(
                recovery_decision(Some(streak)),
                RecoveryDecision::Reset,
                "streak {streak}"
            );
        }
        for streak in [3, 4, u64::MAX] {
            assert_eq!(
                recovery_decision(Some(streak)),
                RecoveryDecision::Stop {
                    code: 20,
                    reason: "recovery_budget_exhausted"
                }
            );
        }
        assert_eq!(
            recovery_decision(None),
            RecoveryDecision::Stop {
                code: 21,
                reason: "recovery_budget_unknown"
            }
        );
        assert_eq!(SERVED_RECOVERY_BUDGET_STOP_CODE, 20);
        assert_eq!(SERVED_RECOVERY_UNKNOWN_STOP_CODE, 21);
    }

    #[test]
    fn the_probe_takes_the_streak_line_before_the_listener_record() {
        let mut probe = ServedReadyProbe::new();
        assert!(!probe.push(b"SSH RECOVERY streak=2\n"));
        assert_eq!(probe.streak(), Some(2));
        assert!(!probe.push(b"SSH RECOVERY streak=x\n"));
        assert_eq!(probe.streak(), Some(2), "a malformed line changes nothing");
        assert!(probe.push(b"SSH LISTENING port=22 authorized_keys=1 preauth_per_source=2\n"));
        assert_eq!(probe.streak(), Some(2));
        let mut later = ServedReadyProbe::new();
        assert!(later.push(b"SSH LISTENING port=22 authorized_keys=1 preauth_per_source=2\n"));
        assert_eq!(
            later.streak(),
            None,
            "readiness without a streak is unknown, not zero"
        );
    }

    #[test]
    fn recovery_startup_word_separates_mode_generation_and_request() {
        let argument = recovery_arg(
            RECOVERY_MODE_APPLY_THEN_FAULT,
            RECOVERY_GENERATION_MASK - 1,
            RECOVERY_REQUEST_MASK - 1,
        );
        assert_eq!(
            argument >> RECOVERY_MODE_SHIFT,
            RECOVERY_MODE_APPLY_THEN_FAULT
        );
        assert_eq!(
            (argument >> RECOVERY_GENERATION_SHIFT) & RECOVERY_GENERATION_MASK,
            RECOVERY_GENERATION_MASK - 1
        );
        assert_eq!(argument & RECOVERY_REQUEST_MASK, RECOVERY_REQUEST_MASK - 1);
    }

    #[test]
    fn client_service_word_separates_phase_generation_and_value() {
        let word = client_service_word(
            CLIENT_SERVICE_COMPLETE_RECONCILE,
            CLIENT_SERVICE_GENERATION_MASK - 1,
            CLIENT_SERVICE_VALUE_MASK - 1,
        );
        assert_eq!(
            client_service_phase(word),
            CLIENT_SERVICE_COMPLETE_RECONCILE
        );
        assert_eq!(
            client_service_generation(word),
            CLIENT_SERVICE_GENERATION_MASK - 1
        );
        assert_eq!(client_service_value(word), CLIENT_SERVICE_VALUE_MASK - 1);
    }

    #[test]
    fn durable_replacement_counts_generations_above_every_field() {
        let step = 40_028_030_045_u64;
        assert_eq!(
            durable_replacement_step(step),
            DURABLE_REPLACEMENT_UNIT + step
        );
        assert_eq!(
            durable_replacement_step(durable_replacement_step(step)) / DURABLE_REPLACEMENT_UNIT,
            2
        );
    }

    #[test]
    fn fuzz_legacy_catalog_excludes_special_start_and_authority_programs() {
        for excluded in [
            INIT,
            MULTI_HANDLE,
            ORPHANER,
            SUPERVISED_WORKER,
            RECOVERY_WORKER,
            SERVICE_CLIENT,
            CLIENT_SERVICE_WORKER,
            ALLOC_PROBE,
            ISOLATION,
            INPUT_STREAM,
            EXTERNAL_WORKLOAD,
            BLOCK_PROBE,
            EXTERNAL_READER,
            OWNER_1,
            OWNER_2,
            OWNER_3,
            OWNER_4,
            NIC_PROBE,
            FILE_SERVER,
            HOSTILE_PROBE,
        ] {
            assert!(!FUZZ_LEGACY_PROGRAMS.contains(&excluded));
        }
        assert!(
            FUZZ_LEGACY_PROGRAMS
                .iter()
                .all(|&index| index < NAMES.len() as u64 && index != MULTI_HANDLE)
        );
        for (position, program) in FUZZ_LEGACY_PROGRAMS.iter().enumerate() {
            assert!(!FUZZ_LEGACY_PROGRAMS[..position].contains(program));
        }
    }

    #[test]
    fn input_stream_fixture_has_the_published_digest() {
        let mut digest = 0x811c_9dc5u32;
        for index in 0..INPUT_STREAM_BYTES {
            digest = (digest ^ input_stream_byte(index) as u32).wrapping_mul(0x0100_0193);
        }
        assert_eq!(digest, INPUT_STREAM_DIGEST);
    }

    /// Both services beat on every pass: no verdict but Live, at any
    /// cadence under the bound.
    #[test]
    fn served_liveness_is_live_while_both_cells_move() {
        let mut judge = ServedLiveness::new();
        assert_eq!(
            judge.observe(5, 0, 0),
            LivenessVerdict::Live,
            "before start"
        );
        judge.start(1_000, 7, 3);
        let mut sshd = 7;
        let mut fsd = 3;
        for pass in 1..2_000u64 {
            if pass % 3 == 0 {
                sshd += 1;
            }
            if pass % 500 == 0 {
                fsd += 1;
            }
            let now = 1_000 + pass * 100;
            assert_eq!(
                judge.observe(now, sshd, fsd),
                LivenessVerdict::Live,
                "pass {pass}"
            );
        }
    }

    /// The worker stops beating while the file server goes on: the worker
    /// is named exactly at the bound, with both idle counts reported, and
    /// not one observation earlier.
    #[test]
    fn served_liveness_names_a_stalled_worker_at_the_bound() {
        let mut judge = ServedLiveness::new();
        judge.start(10_000, 1, 1);
        let mut fsd = 1;
        let mut now = 10_000;
        while now + 100 < 10_000 + SERVED_LIVENESS_TICKS {
            now += 100;
            fsd += 1;
            assert_eq!(
                judge.observe(now, 1, fsd),
                LivenessVerdict::Live,
                "tick {now}"
            );
        }
        now += 100;
        fsd += 1;
        assert_eq!(
            judge.observe(now, 1, fsd),
            LivenessVerdict::Stale {
                component: ServedComponent::Worker,
                idle_ticks: SERVED_LIVENESS_TICKS,
                sshd_idle_ticks: SERVED_LIVENESS_TICKS,
                fsd_idle_ticks: 0,
            }
        );
    }

    /// Both stop at once (a file server that stopped serving takes sshd
    /// with it): the file server is the component named.
    #[test]
    fn served_liveness_names_the_file_server_when_both_are_stale() {
        let mut judge = ServedLiveness::new();
        judge.start(0, 4, 9);
        let mut now = 0;
        let mut verdict = LivenessVerdict::Live;
        while verdict == LivenessVerdict::Live {
            now += 100;
            verdict = judge.observe(now, 4, 9);
        }
        assert_eq!(
            verdict,
            LivenessVerdict::Stale {
                component: ServedComponent::FileServer,
                idle_ticks: SERVED_LIVENESS_TICKS,
                sshd_idle_ticks: SERVED_LIVENESS_TICKS,
                fsd_idle_ticks: SERVED_LIVENESS_TICKS,
            }
        );
        assert_eq!(now, SERVED_LIVENESS_TICKS);
        assert_eq!(ServedComponent::FileServer.name(), "fsd");
        assert_eq!(ServedComponent::Worker.name(), "sshd");
        assert_ne!(
            ServedComponent::FileServer.unresponsive_reason(),
            ServedComponent::Worker.unresponsive_reason()
        );
    }

    /// Init itself did not run across the interval (a stopped guest, a
    /// device wait inside the kernel): the interval is reported as a gap
    /// and never judged, even though both cells are unchanged for far
    /// longer than the bound. Judgment resumes from the gap, so a service
    /// that really is stalled is still named one bound later.
    #[test]
    fn served_liveness_tick_jump_rule_never_judges_an_unwitnessed_interval() {
        let mut judge = ServedLiveness::new();
        judge.start(0, 1, 1);
        assert_eq!(judge.observe(100, 1, 1), LivenessVerdict::Live);
        let jump = 100 + 3 * SERVED_LIVENESS_TICKS;
        assert_eq!(
            judge.observe(jump, 1, 1),
            LivenessVerdict::Gap {
                ticks: 3 * SERVED_LIVENESS_TICKS
            }
        );
        let mut now = jump;
        while now + 100 < jump + SERVED_LIVENESS_TICKS {
            now += 100;
            assert_eq!(
                judge.observe(now, 1, 1),
                LivenessVerdict::Live,
                "tick {now}"
            );
        }
        now += 100;
        assert!(matches!(
            judge.observe(now, 1, 1),
            LivenessVerdict::Stale {
                component: ServedComponent::FileServer,
                ..
            }
        ));
        // A gap exactly at the rule's bound is still an ordinary pass.
        let mut judge = ServedLiveness::new();
        judge.start(0, 1, 1);
        assert_eq!(
            judge.observe(SERVED_LIVENESS_GAP_TICKS, 2, 2),
            LivenessVerdict::Live
        );
        assert_eq!(
            judge.observe(2 * SERVED_LIVENESS_GAP_TICKS + 1, 2, 2),
            LivenessVerdict::Gap {
                ticks: SERVED_LIVENESS_GAP_TICKS + 1
            }
        );
    }

    /// The file server stalls one pass after sshd's last beat (sshd beats
    /// at its loop top, then sends the request the file server never
    /// answers): sshd crosses the bound first, but the file server is the
    /// component named, one pass later, because sshd is never named while
    /// the file server has been quiet for half the bound.
    #[test]
    fn served_liveness_names_the_file_server_that_stalled_a_pass_after_sshd() {
        let mut judge = ServedLiveness::new();
        judge.start(0, 1, 1);
        // sshd's last change is seen at tick 100, the file server's at 200.
        assert_eq!(judge.observe(100, 2, 1), LivenessVerdict::Live);
        assert_eq!(judge.observe(200, 2, 2), LivenessVerdict::Live);
        let mut now = 200;
        while now + 100 < 100 + SERVED_LIVENESS_TICKS {
            now += 100;
            assert_eq!(
                judge.observe(now, 2, 2),
                LivenessVerdict::Live,
                "tick {now}"
            );
        }
        now += 100;
        assert_eq!(
            now,
            100 + SERVED_LIVENESS_TICKS,
            "sshd crosses the bound here"
        );
        assert_eq!(judge.observe(now, 2, 2), LivenessVerdict::Live);
        now += 100;
        assert_eq!(
            judge.observe(now, 2, 2),
            LivenessVerdict::Stale {
                component: ServedComponent::FileServer,
                idle_ticks: SERVED_LIVENESS_TICKS,
                sshd_idle_ticks: SERVED_LIVENESS_TICKS + 100,
                fsd_idle_ticks: SERVED_LIVENESS_TICKS,
            }
        );
        // The file server beating steadily keeps the worker's verdict
        // exact, even when the file server's last beat is recent but not
        // in this very pass.
        let mut judge = ServedLiveness::new();
        judge.start(0, 1, 1);
        let mut fsd = 1;
        let mut now = 0;
        let mut verdict = LivenessVerdict::Live;
        while verdict == LivenessVerdict::Live {
            now += 100;
            if now % 1_000 == 0 {
                fsd += 1;
            }
            verdict = judge.observe(now, 1, fsd);
        }
        assert!(matches!(
            verdict,
            LivenessVerdict::Stale {
                component: ServedComponent::Worker,
                ..
            }
        ));
        assert_eq!(now, SERVED_LIVENESS_TICKS);
    }

    /// A beat that arrives after a long silence resets that service's
    /// witness: idleness is measured from the last change, not summed,
    /// so the bound counts again from the late beat.
    #[test]
    fn served_liveness_a_late_beat_restarts_the_witness() {
        let mut judge = ServedLiveness::new();
        judge.start(0, 1, 1);
        let late = SERVED_LIVENESS_TICKS - 100;
        let mut now = 0;
        while now < late {
            now += 100;
            let versions = if now == late { (2, 2) } else { (1, 1) };
            assert_eq!(
                judge.observe(now, versions.0, versions.1),
                LivenessVerdict::Live,
                "tick {now}"
            );
        }
        while now + 100 < late + SERVED_LIVENESS_TICKS {
            now += 100;
            assert_eq!(
                judge.observe(now, 2, 2),
                LivenessVerdict::Live,
                "tick {now}"
            );
        }
        now += 100;
        assert_eq!(now, late + SERVED_LIVENESS_TICKS);
        assert_eq!(
            judge.observe(now, 2, 2),
            LivenessVerdict::Stale {
                component: ServedComponent::FileServer,
                idle_ticks: SERVED_LIVENESS_TICKS,
                sshd_idle_ticks: SERVED_LIVENESS_TICKS,
                fsd_idle_ticks: SERVED_LIVENESS_TICKS,
            }
        );
    }
}
