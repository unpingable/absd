//! Bootstrap-only admission policy. All transitions run under kernel serialization.

/// Called before constructing init: every byte not currently allocatable is
/// measured boot overhead (including untracked and partial-page usable RAM).
/// No user allocation has yet consumed any of the three commitments.
pub fn boot_minimum_bytes(usable: u64, free_frames: u64, total_frames: u64) -> Option<u64> {
    let overhead = usable.checked_sub(free_frames.checked_mul(4096)?)?;
    overhead.checked_add(total_frames.checked_mul(4096)?)
}

#[cfg(test)]
mod boot_tests {
    use super::*;
    #[test]
    fn backing_not_nominal_ram_controls_admission() {
        let total = 35194;
        for nominal in [128, 256, 512] {
            let usable = nominal * 1024 * 1024 - 131072;
            let free = (usable - 8 * 1024 * 1024) / 4096;
            let minimum = boot_minimum_bytes(usable, free, total).unwrap();
            assert_eq!(usable >= minimum, nominal >= 256);
        }
        let usable = 256 * 1024 * 1024 - 131072;
        assert_eq!(boot_minimum_bytes(usable, total, total), Some(usable));
        assert!(boot_minimum_bytes(usable, total - 1, total).unwrap() > usable);
        assert!(boot_minimum_bytes(usable, total + 1, total).unwrap() < usable);
        assert_eq!(boot_minimum_bytes(0, 1, total), None);
        assert_eq!(boot_minimum_bytes(0, 0, u64::MAX), None);
    }
}
use crate::{object::PipeId, program::ServedReadyProbe};

pub const MIN_SERVED_RAM_BYTES: u64 = 268435456;

pub struct BootstrapAdmission {
    init: Option<u64>,
    stream: Option<PipeId>,
    bound: bool,
    closed: bool,
    probe: ServedReadyProbe,
}
impl Default for BootstrapAdmission {
    fn default() -> Self {
        Self::new()
    }
}
impl BootstrapAdmission {
    pub const fn new() -> Self {
        Self {
            init: None,
            stream: None,
            bound: false,
            closed: false,
            probe: ServedReadyProbe::new(),
        }
    }
    pub fn designate(&mut self, pid: u64) {
        assert!(self.init.is_none() && !self.closed);
        self.init = Some(pid);
    }
    pub fn allowed(&self, pid: u64, granted: bool) -> bool {
        cfg!(absd_mutant_frame_authority) || (granted && self.init == Some(pid) && !self.closed)
    }
    /// PipeId includes its incarnation. Keeping it never grants pipe rights or
    /// changes EOF, and a recycled slot cannot match this identity.
    pub fn bind(&mut self, pid: u64, stream: PipeId) {
        if self.init == Some(pid) && !self.bound && !self.closed {
            self.stream = Some(stream);
            self.bound = true;
        }
    }
    pub fn delivered(&mut self, pid: u64, stream: PipeId, bytes: &[u8]) -> bool {
        if self.init == Some(pid)
            && self.stream == Some(stream)
            && !self.closed
            && self.probe.push(bytes)
        {
            self.closed = true;
            self.stream = None;
            return true;
        }
        false
    }
    pub fn retire(&mut self, pid: u64) {
        if self.init == Some(pid) {
            self.closed = true;
            self.stream = None;
        }
    }
}

pub use crate::frame_geometry::construction_frames;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{elf, layout};
    const READY: &[u8] = b"SSH LISTENING port=22 authorized_keys=1 preauth_per_source=2\n";
    #[test]
    fn ready_is_bound_incremental_and_irreversible() {
        let mut gate = BootstrapAdmission::new();
        let pipe = PipeId::for_tests(1);
        gate.designate(42);
        assert!(gate.allowed(42, true));
        assert!(!gate.allowed(1, true));
        assert!(!gate.allowed(42, false));
        gate.bind(42, pipe);
        assert!(!gate.delivered(43, pipe, READY));
        assert!(!gate.delivered(42, PipeId::for_tests(2), READY));
        assert!(!gate.delivered(
            42,
            pipe,
            b"diagnostic SSH LISTENING port=22 authorized_keys=1\n"
        ));
        assert!(!gate.delivered(
            42,
            pipe,
            b"SSH LISTENING port=22 authorized_keys=0 preauth_per_source=2\n"
        ));
        assert!(!gate.delivered(42, pipe, &READY[..11]));
        assert!(gate.delivered(42, pipe, &READY[11..]));
        assert!(!gate.allowed(42, true));
        gate.bind(42, PipeId::for_tests(2));
        assert!(!gate.allowed(42, true));
    }
    #[test]
    fn reused_pipe_and_overflow_cannot_close_or_rebind_generation() {
        let mut pipes = crate::object::PipeTable::new();
        let pipe = pipes
            .create(crate::handle::RIGHT_READ | crate::handle::RIGHT_WRITE)
            .unwrap();
        let mut gate = BootstrapAdmission::new();
        gate.designate(7);
        gate.bind(7, pipe);
        assert!(!gate.delivered(7, pipe, &[b'x'; 97]));
        assert!(!gate.delivered(7, pipe, READY));
        assert!(gate.allowed(7, true));
        pipes.release(pipe, true, true).unwrap();
        let replacement = pipes
            .create(crate::handle::RIGHT_READ | crate::handle::RIGHT_WRITE)
            .unwrap();
        assert_ne!(replacement, pipe);
        gate.bind(7, replacement);
        assert!(!gate.delivered(7, replacement, READY));
        assert!(gate.allowed(7, true));
        gate.retire(7);
        assert!(!gate.allowed(7, true));
    }

    #[test]
    fn teardown_closes_even_without_self_admission_or_ready() {
        let mut gate = BootstrapAdmission::new();
        gate.designate(9);
        gate.retire(9);
        assert!(!gate.allowed(9, true));
    }
    #[test]
    fn construction_charge_counts_distinct_tables_and_rejects_overlap() {
        let mut image = elf::Image {
            entry: layout::USER_IMAGE_MIN,
            segments: [elf::LoadSegment::EMPTY; elf::MAX_LOAD_SEGMENTS],
            segment_count: 1,
        };
        image.segments[0].virtual_address = layout::USER_IMAGE_MIN;
        image.segments[0].memory_size = 4097;
        assert_eq!(construction_frames(&image), Some(17)); // 2 image + 2 stack + 2 leaf + 3 upper + 8 kernel
        image.segments[1] = image.segments[0];
        image.segment_count = 2;
        assert_eq!(construction_frames(&image), None);
    }
}

/// The supported dispatch table, shared by both architecture entry paths.
/// Hidden numbers terminate here without invoking either privileged handler.
pub fn dispatch(
    number: u64,
    admit: impl FnOnce() -> i64,
    spawn: impl FnOnce() -> i64,
) -> Option<i64> {
    match number {
        crate::syscall::SYS_FRAME_ADMIT_SELF => Some(admit()),
        crate::syscall::SYS_SPAWN_RESERVED_COPY => Some(spawn()),
        0x7ff0..=0x7ff5 => Some(crate::syscall::ERROR_NOT_IMPLEMENTED),
        _ => None,
    }
}
#[cfg(test)]
mod dispatch_tests {
    use super::*;
    #[test]
    fn supported_dispatch_never_routes_private_calls_even_for_init() {
        for number in 0x7ff0..=0x7ff5 {
            assert_eq!(
                dispatch(
                    number,
                    || panic!("private self"),
                    || panic!("private spawn")
                ),
                Some(-38)
            );
        }
        assert_eq!(dispatch(45, || 123, || panic!("wrong handler")), Some(123));
        assert_eq!(dispatch(46, || panic!("wrong handler"), || 456), Some(456));
        assert_eq!(
            dispatch(44, || panic!("old call"), || panic!("old call")),
            None
        );
    }
}

/// Authority precedes every argument and caller-memory observation.
pub fn admit_self(
    frames: &mut crate::memory::FrameAllocator,
    pid: u32,
    allowed: bool,
    total: u64,
    reserved1: u64,
    reserved2: u64,
) -> i64 {
    use crate::syscall::*;
    if !allowed {
        return ERROR_RIGHTS;
    }
    if reserved1 != 0 || reserved2 != 0 || !(1..=MAX_FRAME_ADMISSION_FRAMES).contains(&total) {
        return ERROR_INVALID;
    }
    match frames.admit(pid, total as usize) {
        Ok(()) => 0,
        Err(
            crate::memory::AdmissionError::NoCapacity | crate::memory::AdmissionError::NoRecord,
        ) => ERROR_NO_MEMORY,
        Err(_) => ERROR_INVALID,
    }
}

pub fn read_request(
    allowed: bool,
    reserved1: u64,
    reserved2: u64,
    copy: impl FnOnce(&mut [u8; crate::syscall::SPAWN_RESERVED_REQUEST_BYTES]) -> bool,
) -> Result<crate::syscall::SpawnReservedRequest, i64> {
    use crate::syscall::*;
    if !allowed {
        return Err(ERROR_RIGHTS);
    }
    if reserved1 != 0 || reserved2 != 0 {
        return Err(ERROR_INVALID);
    }
    let mut raw = [0; SPAWN_RESERVED_REQUEST_BYTES];
    if !copy(&mut raw) {
        return Err(ERROR_FAULT);
    }
    let request = SpawnReservedRequest::from_bytes(&raw);
    if request.program_and_flags & !SPAWN_PROGRAM_MASK & !SPAWN_NO_SPAWN != 0
        || request.copies_count > MAX_SPAWN_HANDLES as u64
        || !(1..=MAX_FRAME_ADMISSION_FRAMES).contains(&request.total_frames)
    {
        return Err(ERROR_INVALID);
    }
    Ok(request)
}

#[cfg(test)]
mod refusal_tests {
    use super::*;
    use crate::{
        memory::{FrameAllocator, FrameOwner},
        syscall::*,
    };
    #[test]
    fn authority_precedes_bad_memory_and_reserved_words() {
        assert_eq!(
            read_request(false, 1, 1, |_| panic!("read before authority")),
            Err(-1)
        );
        assert_eq!(
            read_request(true, 1, 0, |_| panic!("read reserved request")),
            Err(-22)
        );
        assert_eq!(read_request(true, 0, 0, |_| false), Err(-14));
        for (flags, count, total, expected) in [
            (0, 0, 1, true),
            (SPAWN_NO_SPAWN, 64, 65536, true),
            (SPAWN_CONSOLE, 0, 1, false),
            (0, 65, 1, false),
            (0, 0, 0, false),
            (0, 0, 65537, false),
        ] {
            let request = SpawnReservedRequest {
                program_and_flags: flags,
                copies_address: u64::MAX,
                copies_count: count,
                total_frames: total,
            };
            let result = read_request(true, 0, 0, |out| {
                *out = request.to_bytes();
                true
            });
            assert_eq!(result.is_ok(), expected);
        }
    }
    #[test]
    fn self_refusals_preserve_retry_and_owned_frame_accounting() {
        let mut frames = FrameAllocator::new();
        frames.add_usable(4096, 9 * 4096);
        frames
            .allocate_contiguous(2, FrameOwner::UserPage(7))
            .unwrap();
        assert_eq!(admit_self(&mut frames, 7, false, 0, 1, 1), -1);
        for total in [0, 1, 65537] {
            assert_eq!(admit_self(&mut frames, 7, true, total, 0, 0), -22);
        }
        assert_eq!(admit_self(&mut frames, 7, true, 9, 0, 0), -12);
        assert_eq!(frames.reservation(7), None);
        assert_eq!(admit_self(&mut frames, 7, true, 8, 0, 0), 0);
        assert_eq!(frames.reservation(7), Some((8, 2)));
        assert_eq!(frames.allocated_frames(), 2);
        assert_eq!(admit_self(&mut frames, 7, true, 8, 0, 0), -22);
        assert_eq!(admit_self(&mut frames, 7, false, 8, 0, 0), -1);
        assert_eq!(frames.reservation(7), Some((8, 2)));
    }
}
