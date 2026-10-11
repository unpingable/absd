#[derive(Clone, Copy)]
pub struct EmbeddedProgram {
    pub name: &'static str,
    pub bytes: &'static [u8],
}
pub const PROGRAMS: [EmbeddedProgram; 44] = {
    let mut p = [EmbeddedProgram {
        name: "unported",
        bytes: &[],
    }; 44];
    p[0] = EmbeddedProgram {
        name: "init",
        bytes: include_bytes!(env!("ABSD_ARM_INIT_ELF")),
    };
    p[1] = EmbeddedProgram {
        name: "hello-a",
        bytes: include_bytes!(env!("ABSD_ARM_INIT_ELF")),
    };
    p[3] = EmbeddedProgram {
        name: "exit7",
        bytes: include_bytes!(env!("ABSD_ARM_EXIT7_ELF")),
    };
    p[4] = EmbeddedProgram {
        name: "fault",
        bytes: include_bytes!(env!("ABSD_ARM_FAULT_ELF")),
    };
    p
};

pub fn uses_multi_start(_: usize) -> bool {
    false
}
