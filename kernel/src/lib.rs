#![no_std]
pub use absd_abi::{layout, nic, program, syscall};

pub mod arch;
pub mod e1000_ring;
pub mod elf;
pub mod handle;
pub mod memory;
pub mod object;
pub mod process;
pub mod rt;
pub mod rtc;
pub mod survey_facts;
pub mod user_memory;
#[cfg(target_arch = "x86_64")]
pub mod user_program;
#[cfg(target_arch = "aarch64")]
#[path = "arch/aarch64/program.rs"]
pub mod user_program;

pub mod run_queue;
pub mod topology;

pub mod virtio_completion;

pub mod owner_lock;
