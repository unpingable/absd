//! nix 0.29.0 is `#![cfg(unix)]`: on a non-Unix target it compiles to an
//! empty crate. On ABSD the configured-away crate still receives the `std`
//! prelude, which the restricted-`std` target refuses without a feature gate
//! that the same `cfg` removes. This substitute is that empty crate, `no_std`.
//! It refuses to build on Unix, where the real crate must be used.
#![no_std]
#[cfg(unix)]
compile_error!("nix-absd substitutes nix only on non-Unix targets");
