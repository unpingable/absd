// Keep private MWM selection out of stock init and the shared user library:
// even inactive additions there change embedded ELF identities.
#[cfg(not(feature = "mwm-successor"))]
#[path = "mwm_coordinator_g1.rs"]
mod selected;
#[cfg(feature = "mwm-successor")]
#[path = "mwm_successor_guest.rs"]
mod selected;

pub use selected::run;
