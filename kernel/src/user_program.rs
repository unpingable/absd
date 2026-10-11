//! Ordinary, separately linked ELF64 programs embedded for the current
//! filesystem-free boot stage. `spawn` names a program by its index here.

pub struct EmbeddedProgram {
    pub name: &'static str,
    pub bytes: &'static [u8],
}

pub const PROGRAMS: [EmbeddedProgram; 44] = [
    EmbeddedProgram {
        name: "init",
        bytes: include_bytes!(env!("ABSD_USER_INIT_ELF")),
    },
    EmbeddedProgram {
        name: "hello-a",
        bytes: include_bytes!(env!("ABSD_USER_HELLO_A_ELF")),
    },
    EmbeddedProgram {
        name: "hello-b",
        bytes: include_bytes!(env!("ABSD_USER_HELLO_B_ELF")),
    },
    EmbeddedProgram {
        name: "exit7",
        bytes: include_bytes!(env!("ABSD_USER_EXIT7_ELF")),
    },
    EmbeddedProgram {
        name: "fault",
        bytes: include_bytes!(env!("ABSD_USER_FAULT_ELF")),
    },
    EmbeddedProgram {
        name: "fpu",
        bytes: include_bytes!(env!("ABSD_USER_FPU_ELF")),
    },
    EmbeddedProgram {
        name: "trap",
        bytes: include_bytes!(env!("ABSD_USER_TRAP_ELF")),
    },
    EmbeddedProgram {
        name: "privileged",
        bytes: include_bytes!(env!("ABSD_USER_PRIVILEGED_ELF")),
    },
    EmbeddedProgram {
        name: "heap",
        bytes: include_bytes!(env!("ABSD_USER_HEAP_ELF")),
    },
    EmbeddedProgram {
        name: "unmapped",
        bytes: include_bytes!(env!("ABSD_USER_UNMAPPED_ELF")),
    },
    EmbeddedProgram {
        name: "overflow",
        bytes: include_bytes!(env!("ABSD_USER_OVERFLOW_ELF")),
    },
    EmbeddedProgram {
        name: "cell",
        bytes: include_bytes!(env!("ABSD_USER_CELL_ELF")),
    },
    EmbeddedProgram {
        name: "shared",
        bytes: include_bytes!(env!("ABSD_USER_SHARED_ELF")),
    },
    EmbeddedProgram {
        name: "readonly",
        bytes: include_bytes!(env!("ABSD_USER_READONLY_ELF")),
    },
    EmbeddedProgram {
        name: "watcher",
        bytes: include_bytes!(env!("ABSD_USER_WATCHER_ELF")),
    },
    EmbeddedProgram {
        name: "piper",
        bytes: include_bytes!(env!("ABSD_USER_PIPER_ELF")),
    },
    EmbeddedProgram {
        name: "sleeper",
        bytes: include_bytes!(env!("ABSD_USER_SLEEPER_ELF")),
    },
    EmbeddedProgram {
        name: "shell",
        bytes: include_bytes!(env!("ABSD_USER_SHELL_ELF")),
    },
    EmbeddedProgram {
        name: "fuzz",
        bytes: include_bytes!(env!("ABSD_USER_FUZZ_ELF")),
    },
    EmbeddedProgram {
        name: "multi-handle",
        bytes: include_bytes!(env!("ABSD_USER_MULTI_HANDLE_ELF")),
    },
    EmbeddedProgram {
        name: "stack-grow",
        bytes: include_bytes!(env!("ABSD_USER_STACK_GROW_ELF")),
    },
    EmbeddedProgram {
        name: "stack-jump",
        bytes: include_bytes!(env!("ABSD_USER_STACK_JUMP_ELF")),
    },
    EmbeddedProgram {
        name: "orphaner",
        bytes: include_bytes!(env!("ABSD_USER_ORPHANER_ELF")),
    },
    EmbeddedProgram {
        name: "supervised-worker",
        bytes: include_bytes!(env!("ABSD_USER_SUPERVISED_WORKER_ELF")),
    },
    EmbeddedProgram {
        name: "recovery-worker",
        bytes: include_bytes!(env!("ABSD_USER_RECOVERY_WORKER_ELF")),
    },
    EmbeddedProgram {
        name: "service-client",
        bytes: include_bytes!(env!("ABSD_USER_SERVICE_CLIENT_ELF")),
    },
    EmbeddedProgram {
        name: "client-service-worker",
        bytes: include_bytes!(env!("ABSD_USER_CLIENT_SERVICE_WORKER_ELF")),
    },
    EmbeddedProgram {
        name: "alloc-probe",
        bytes: include_bytes!(env!("ABSD_USER_ALLOC_PROBE_ELF")),
    },
    EmbeddedProgram {
        name: "isolation",
        bytes: include_bytes!(env!("ABSD_USER_ISOLATION_ELF")),
    },
    EmbeddedProgram {
        name: "input-stream",
        bytes: include_bytes!(env!("ABSD_USER_INPUT_STREAM_ELF")),
    },
    EmbeddedProgram {
        name: "external-workload",
        bytes: include_bytes!(env!("ABSD_USER_EXTERNAL_WORKLOAD_ELF")),
    },
    EmbeddedProgram {
        name: "block-probe",
        bytes: include_bytes!(env!("ABSD_USER_BLOCK_PROBE_ELF")),
    },
    EmbeddedProgram {
        name: "external-reader",
        bytes: include_bytes!(env!("ABSD_USER_EXTERNAL_READER_ELF")),
    },
    EmbeddedProgram {
        name: "owner-1",
        bytes: include_bytes!(env!("ABSD_USER_OWNER_1_ELF")),
    },
    EmbeddedProgram {
        name: "owner-2",
        bytes: include_bytes!(env!("ABSD_USER_OWNER_2_ELF")),
    },
    EmbeddedProgram {
        name: "owner-3",
        bytes: include_bytes!(env!("ABSD_USER_OWNER_3_ELF")),
    },
    EmbeddedProgram {
        name: "owner-4",
        bytes: include_bytes!(env!("ABSD_USER_OWNER_4_ELF")),
    },
    EmbeddedProgram {
        name: "nic-probe",
        bytes: include_bytes!(env!("ABSD_USER_NIC_PROBE_ELF")),
    },
    EmbeddedProgram {
        name: "file-server",
        bytes: include_bytes!(env!("ABSD_USER_FILE_SERVER_ELF")),
    },
    EmbeddedProgram {
        name: "machine-probe",
        bytes: include_bytes!(env!("ABSD_USER_MACHINE_PROBE_ELF")),
    },
    EmbeddedProgram {
        name: "hostile-probe",
        bytes: include_bytes!(env!("ABSD_USER_HOSTILE_PROBE_ELF")),
    },
    EmbeddedProgram {
        name: "rt-probe",
        bytes: include_bytes!(env!("ABSD_USER_RT_PROBE_ELF")),
    },
    EmbeddedProgram {
        name: "fpu-mxcsr",
        bytes: include_bytes!(env!("ABSD_USER_FPU_MXCSR_ELF")),
    },
    EmbeddedProgram {
        name: "smp-user",
        bytes: include_bytes!(env!("ABSD_USER_SMP_USER_ELF")),
    },
];

/// Whether a catalog entry expects the ordered handle-vector entry ABI.
/// Keeping this next to the catalog prevents either spawn syscall from
/// launching a program with incompatible meanings for RSI and RDX.
pub const fn uses_multi_start(index: usize) -> bool {
    index == absd_abi::program::MULTI_HANDLE as usize
        || index == absd_abi::program::SERVICE_CLIENT as usize
        || index == absd_abi::program::CLIENT_SERVICE_WORKER as usize
        || index == absd_abi::program::INPUT_STREAM as usize
        || index == absd_abi::program::EXTERNAL_WORKLOAD as usize
        || index == absd_abi::program::BLOCK_PROBE as usize
        || index == absd_abi::program::EXTERNAL_READER as usize
        || index == absd_abi::program::FILE_SERVER as usize
        || (index >= absd_abi::program::OWNER_1 as usize
            && index <= absd_abi::program::OWNER_4 as usize)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn every_user_program_is_an_elf64_image() {
        for program in PROGRAMS {
            assert_eq!(&program.bytes[..5], b"\x7fELF\x02", "{}", program.name);
        }
    }
    #[test]
    fn catalog_order_matches_the_shared_abi() {
        let names: [&str; PROGRAMS.len()] = core::array::from_fn(|index| PROGRAMS[index].name);
        assert_eq!(names, absd_abi::program::NAMES);
        assert_eq!(PROGRAMS[absd_abi::program::INIT as usize].name, "init");
        assert!(!uses_multi_start(absd_abi::program::INIT as usize));
        assert!(uses_multi_start(absd_abi::program::MULTI_HANDLE as usize));
        assert!(!uses_multi_start(
            absd_abi::program::RECOVERY_WORKER as usize
        ));
        assert!(uses_multi_start(absd_abi::program::SERVICE_CLIENT as usize));
        assert!(uses_multi_start(
            absd_abi::program::CLIENT_SERVICE_WORKER as usize
        ));
        assert!(uses_multi_start(absd_abi::program::INPUT_STREAM as usize));
        assert!(uses_multi_start(
            absd_abi::program::EXTERNAL_WORKLOAD as usize
        ));
        assert!(uses_multi_start(absd_abi::program::BLOCK_PROBE as usize));
        assert!(uses_multi_start(
            absd_abi::program::EXTERNAL_READER as usize
        ));
        assert!(uses_multi_start(absd_abi::program::FILE_SERVER as usize));
        for index in absd_abi::program::FUZZ_LEGACY_PROGRAMS {
            assert!(!uses_multi_start(index as usize));
        }
    }
}
