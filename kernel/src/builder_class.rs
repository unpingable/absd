//! #115 builder class (`builder-class-heap`): which processes get the 512 MiB
//! builder heap window, and the frame-admission budget each is admitted with.
//!
//! The class is the subtree of the one designated durable worker. A process
//! is the **worker** only when init (the kernel's own child, parent 0,
//! running the init program) spawns the `external-workload` program in a
//! durable boot, and only once per boot. A child of the worker is a
//! **compiler** (a native batch step); a child of a compiler or tool is a
//! **tool** (assembler, linker). Everything else is ordinary: any other
//! `external-workload`, a second one spawned by init, init itself, the file
//! server and every suite program.
//!
//! No syscall, flag or handle grants a class: the kernel derives it at spawn
//! from the parent's recorded identity and class. Inside the worker's subtree
//! every child is again in the class. Compilers and tools are admitted at
//! construction through the existing frame-admission core with the per-role
//! budget below, never above `MAX_FRAME_ADMISSION_FRAMES`.

use crate::syscall::MAX_FRAME_ADMISSION_FRAMES;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Class {
    Ordinary,
    /// The designated durable worker: ordinary window, roots the class.
    Worker,
    /// A child of the worker.
    Compiler,
    /// A child of a compiler or tool.
    Tool,
}

impl Class {
    /// Whether the process gets the builder class heap window.
    pub const fn builder(self) -> bool {
        matches!(self, Self::Compiler | Self::Tool)
    }
}

/// What the kernel recorded about the parent when it was published.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Parent {
    pub class: Class,
    /// The parent is init: the published process whose own parent is the
    /// kernel (0) and whose program is `init`.
    pub is_init: bool,
}

/// The class of a new process. `parent` is `None` for a kernel-started
/// process or a parent that was never published.
pub fn classify(
    durable: bool,
    program_is_worker: bool,
    parent: Option<Parent>,
    worker_designated: bool,
) -> Class {
    match parent {
        Some(Parent {
            class: Class::Worker,
            ..
        }) => Class::Compiler,
        Some(Parent {
            class: Class::Compiler | Class::Tool,
            ..
        }) => Class::Tool,
        Some(Parent { is_init: true, .. })
            if durable && program_is_worker && !worker_designated =>
        {
            Class::Worker
        }
        _ => Class::Ordinary,
    }
}

const fn budget_or(value: Option<&str>, fallback: usize) -> usize {
    let Some(value) = value else {
        return fallback;
    };
    let bytes = value.as_bytes();
    assert!(!bytes.is_empty());
    let mut total = 0;
    let mut i = 0;
    while i < bytes.len() {
        assert!(bytes[i] >= b'0' && bytes[i] <= b'9');
        total = total * 10 + (bytes[i] - b'0') as usize;
        i += 1;
    }
    total
}

/// Admission budget of a compiler: the unchanged ceiling. The native kernel
/// link owns at most about 126.2k frames (E3 step 55), so the ceiling leaves
/// only about 3.7 %. A larger budget would need a builder-only ceiling in the
/// admission core, which this change does not make. A build may lower it
/// (`ABSD_BUILDER_COMPILER_FRAMES`, refusal qualification only).
pub const COMPILER_FRAMES: usize = budget_or(
    option_env!("ABSD_BUILDER_COMPILER_FRAMES"),
    MAX_FRAME_ADMISSION_FRAMES as usize,
);
/// Admission budget of a tool: the linker owns at most about 53.9k frames.
pub const TOOL_FRAMES: usize = budget_or(option_env!("ABSD_BUILDER_TOOL_FRAMES"), 65536);
/// Admission budget of the durable file server (init's child), so the
/// builder's reservations run beside another process's commitment.
pub const FILE_SERVER_FRAMES: usize = budget_or(option_env!("ABSD_BUILDER_FSD_FRAMES"), 4096);

/// The construction budget for a new process of `class`; the file server is
/// identified by its program and by init as its parent.
pub const fn budget(class: Class, durable_file_server: bool) -> Option<usize> {
    match class {
        Class::Compiler => Some(COMPILER_FRAMES),
        Class::Tool => Some(TOOL_FRAMES),
        Class::Ordinary if durable_file_server => Some(FILE_SERVER_FRAMES),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::memory::{FrameAllocator, FrameOwner};
    const INIT: Option<Parent> = Some(Parent {
        class: Class::Ordinary,
        is_init: true,
    });
    const ORDINARY: Option<Parent> = Some(Parent {
        class: Class::Ordinary,
        is_init: false,
    });
    fn child_of(class: Class) -> Option<Parent> {
        Some(Parent {
            class,
            is_init: false,
        })
    }

    #[test]
    fn only_inits_first_durable_worker_spawn_roots_the_class() {
        assert_eq!(classify(true, true, INIT, false), Class::Worker);
        // At most once per boot.
        assert_eq!(classify(true, true, INIT, true), Class::Ordinary);
        // Any other parent: the file server, a suite program, the kernel.
        assert_eq!(classify(true, true, ORDINARY, false), Class::Ordinary);
        assert_eq!(classify(true, true, None, false), Class::Ordinary);
        // Not a durable boot, or not the worker program.
        assert_eq!(classify(false, true, INIT, false), Class::Ordinary);
        assert_eq!(classify(true, false, INIT, false), Class::Ordinary);
    }

    #[test]
    fn the_class_is_inherited_only_through_the_worker_subtree() {
        for (durable, worker, designated) in [
            (true, false, true),
            (true, true, true),
            (false, false, false),
        ] {
            assert_eq!(
                classify(durable, worker, child_of(Class::Worker), designated),
                Class::Compiler
            );
            for parent in [Class::Compiler, Class::Tool] {
                assert_eq!(
                    classify(durable, worker, child_of(parent), designated),
                    Class::Tool
                );
            }
        }
        assert!(Class::Compiler.builder() && Class::Tool.builder());
        assert!(!Class::Worker.builder() && !Class::Ordinary.builder());
        assert_eq!(classify(true, false, ORDINARY, true), Class::Ordinary);
        assert_eq!(classify(true, false, INIT, true), Class::Ordinary);
    }

    #[test]
    fn budgets_stay_inside_the_unchanged_ceiling() {
        assert_eq!(MAX_FRAME_ADMISSION_FRAMES, 131072);
        assert_eq!(COMPILER_FRAMES, 131072);
        assert_eq!(TOOL_FRAMES, 65536);
        assert_eq!(FILE_SERVER_FRAMES, 4096);
        assert_eq!(budget(Class::Compiler, false), Some(131072));
        assert_eq!(budget(Class::Tool, true), Some(65536));
        assert_eq!(budget(Class::Ordinary, true), Some(4096));
        assert_eq!(budget(Class::Ordinary, false), None);
        assert_eq!(budget(Class::Worker, false), None);
    }

    #[test]
    fn admission_refuses_a_builder_budget_above_the_ceiling_and_caps_one_inside_it() {
        let mut frames = FrameAllocator::new();
        frames.add_usable(4096, 33 * 4096);
        // A compiler budget one above the ceiling is refused with no record:
        // the spawn that asked for it fails before any frame is allocated.
        assert_eq!(
            frames.admit(7, COMPILER_FRAMES + 1),
            Err(crate::memory::AdmissionError::Invalid)
        );
        assert_eq!(frames.reservation(7), None);
        // Inside the ceiling, a reservation caps the process, whatever its
        // heap window, and keeps another process's commitment intact.
        assert_eq!(frames.admit(8, 4), Ok(()));
        assert_eq!(frames.admit(7, 16), Ok(()));
        for _ in 0..16 {
            frames.allocate(FrameOwner::UserPage(7)).unwrap();
        }
        assert!(frames.allocate(FrameOwner::UserPage(7)).is_none());
        // An unreserved process cannot take the file server's idle frames.
        for _ in 0..12 {
            frames.allocate(FrameOwner::UserPage(9)).unwrap();
        }
        assert!(frames.allocate(FrameOwner::UserPage(9)).is_none());
        for _ in 0..4 {
            frames.allocate(FrameOwner::UserPage(8)).unwrap();
        }
        assert_eq!(frames.reservation(8), Some((4, 4)));
    }
}
