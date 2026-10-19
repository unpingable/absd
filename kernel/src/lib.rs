#![no_std]
pub use absd_abi::{layout, nic, program, syscall};

pub mod acpi;
pub mod arch;
pub mod e1000_ring;
pub mod elf;
pub mod handle;
pub mod i219;
pub mod i219_pci;
pub mod i219_ring;
pub mod memory;
pub mod nvme_ready;
pub mod object;
pub mod process;
pub mod ram_plan;
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
pub mod xhci_legacy;
pub mod xhci_ring;
pub mod xhci_scratch;

pub mod console_input;
pub mod interrupt_vector;
pub mod owner_lock;

#[cfg(all(
    feature = "frame-admission-v0",
    feature = "frame-reservation-experiment"
))]
compile_error!("supported frame admission cannot include private dispatch");

#[cfg(feature = "frame-admission-v0")]
pub mod frame_admission;

pub mod frame_geometry;
pub mod pci_interrupt;
pub mod usb_keyboard;
pub mod xhci_irq;
