#![no_std]
#[cfg(test)]
#[macro_use]
extern crate std;
pub use absd_abi::{layout, nic, program, syscall};

// Admission accounting builds with the builder envelope; a reserved process
// maps only the SERVICE_HEAP_PAGES heap it was charged, and the host fixture
// (examples/large_envelope_admission.rs) covers that. The served dispatch
// stays refused with the envelope in every normal build.
#[cfg(all(feature = "builder-large-envelope", feature = "frame-admission-v0"))]
compile_error!("builder-large-envelope cannot be combined with served frame admission");
// The kernel's feature and the ABI layout it compiles against must agree:
// `--features absd-abi/builder-large-envelope` alone would give the kernel the
// envelope layout while build.rs budgets and the embedded programs, which key
// on the kernel feature, keep the default one (and would slip past the guard).
const _: () = assert!(
    cfg!(feature = "builder-large-envelope") == layout::BUILDER_LARGE_ENVELOPE,
    "absd-abi builder-large-envelope must come with the kernel feature"
);
// The same holds for the builder resource profile: an ABI-only selection would
// give the kernel 16-page stacks and the 384 MiB heap while build.rs budgets
// and the embedded programs keep the defaults.
const _: () = assert!(
    cfg!(feature = "builder-profile") == layout::BUILDER_PROFILE,
    "absd-abi builder-profile must come with the kernel feature"
);

pub mod acpi;
pub mod ahci_command;
pub mod amdvi;
pub mod ap_page;
pub mod arch;
pub mod byte_move;
pub mod civil_clock;
pub mod defer_log;
pub mod dma_contain;
pub mod dma_policy;
pub mod e1000_ring;
pub mod elf;
pub mod handle;
pub mod i219;
pub mod i219_pci;
pub mod i219_ring;
pub mod ivrs;
pub mod mcfg;
pub mod memory;
pub mod nic_link;
pub mod nvme_ready;
pub mod object;
pub mod observation;
pub mod operator_policy;
pub mod process;
pub mod ram_plan;
pub mod readable_wait;
pub mod rt;
pub mod rtc;
pub mod rtl8125;
pub mod rtl8125_pci;
pub mod rtl8125_ring;
pub mod storage_fence;
pub mod survey_facts;
pub mod user_memory;
// Exercise the final-binary-only stack audit in the ordinary host test suite.
#[cfg(test)]
mod stack_growth_audit;
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
pub mod console_presentation;
pub mod interrupt_vector;
pub mod kernel_log;
pub mod owner_lock;

#[cfg(all(
    feature = "frame-admission-v0",
    feature = "frame-reservation-experiment"
))]
compile_error!("supported frame admission cannot include private dispatch");

#[cfg(feature = "frame-admission-v0")]
pub mod frame_admission;

#[cfg(feature = "mwm-experiment")]
pub mod display;
pub mod frame_geometry;
pub mod gpt;
pub mod pci_interrupt;
pub mod usb_keyboard;
pub mod xhci_irq;

pub mod ata_dma;
pub mod sound_queue;

pub mod sound_pci;

pub mod sound_protocol;

/// The ARM64 device-tree reader, compiled on the host for its tests.
#[cfg(test)]
#[allow(dead_code)]
#[path = "arch/aarch64/fdt.rs"]
mod arm64_fdt;
#[cfg(test)]
mod arm64_fdt_tests;

pub mod pci_selection;

// #115 builder class heap: a variant of the 384 MiB builder profile only; it
// admits through the frame-admission core and never in a served build.
#[cfg(feature = "builder-class-heap")]
pub mod builder_class;
#[cfg(all(feature = "builder-class-heap", feature = "frame-admission-v0"))]
compile_error!("builder-class-heap cannot be combined with served frame admission");
#[cfg(all(feature = "builder-class-heap", feature = "builder-large-envelope"))]
compile_error!("builder-class-heap cannot be combined with builder-large-envelope");
const _: () = assert!(
    cfg!(feature = "builder-class-heap") == layout::BUILDER_CLASS_HEAP,
    "absd-abi builder-class-heap must come with the kernel feature"
);

#[cfg(test)]
mod kernel_log_tests;
pub mod native_installer;
#[cfg(test)]
mod native_installer_tests;
// Pure init terminal rules are covered by the ordinary kernel host gate.
#[cfg(test)]
#[path = "../user/src/console_router.rs"]
mod local_console_router;
#[cfg(test)]
mod local_console_snapshot_tests;
#[cfg(test)]
#[path = "../user/src/console_startup.rs"]
mod local_console_startup;
#[cfg(test)]
#[path = "../user/src/console_text.rs"]
mod local_console_text;
