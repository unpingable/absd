# Vendored crates

Origin, licence and local changes for each directory here. The four
directories are content-pinned by `scripts/verify-inputs.sh`, so this file
and the repository's `REUSE.toml` and `LICENSES/` carry the attribution
instead of files inside them. `provenance.toml` is the checked record.

<!-- REUSE-IgnoreStart -->

## tempfile

Upstream: `tempfile` 3.27.0 from crates.io (`.cargo_vcs_info.json` sha1
`5c8fa12eb584931b4f1bccfde87eb72fbfa7dc61`). Licence: MIT OR Apache-2.0;
upstream's `LICENSE-MIT` ("Copyright (c) 2015 Steven Allen") and
`LICENSE-APACHE` are kept in the directory.

Changed from the upstream archive, for ABSD:

- `src/file/imp/mod.rs`: one added line routes `target_os = "absd"` to
  `absd.rs`, and `target_os = "absd"` is added to the `not(any(...))` list
  on the fallback module.
- `src/lib.rs`: one added line, `#![cfg_attr(target_os = "absd",
  feature(absd_fs_ext))]`.
- `src/file/imp/absd.rs`: new file, not from upstream.

Everything else is byte-identical to the archive. The licence of the ABSD
lines and of `absd.rs` is not decided.

## rustc-literal-escaper

Upstream: `rust-lang/literal-escaper` v0.0.5
(https://github.com/rust-lang/literal-escaper/tree/v0.0.5), taken in the
form `proc-macro2` 1.0.106 embeds it: `src/lib.rs` is that crate's
`src/rustc_literal_escaper.rs` and `src/num.rs` is its `src/num.rs`
(byte-identical). Both upstreams are MIT OR Apache-2.0 (literal-escaper's
manifest writes it "Apache-2.0 OR MIT"), and their `LICENSE-MIT` and
`LICENSE-APACHE` files are the same bytes. Neither states a copyright line.
The texts are `LICENSES/MIT.txt` and `LICENSES/Apache-2.0.txt`.

Changed from the `proc-macro2` copy, for ABSD: `src/lib.rs` gains
`#![no_std]` and `mod num;` (four lines with their blank lines).
`Cargo.toml` is written here so the crate resolves inside the staged
standard-library workspace. The licence of those changes is not decided.

Build-only: `scripts/stage-library.sh` copies it into the staged library as
`proc_macro`'s dependency.

## ctrlc-stub, nix-absd

Not vendored upstream code. Each is a first-party crate that takes the name
and version of the crate it substitutes for and contains none of its source.
Their manifests used to carry the substituted crate's licence string (`MIT OR
Apache-2.0`, `MIT`), written with the stub and never an owner decision; the
owner had the fields removed on 2026-10-10. `provenance.toml` lists both as
first-party with the licence pending.

<!-- REUSE-IgnoreEnd -->
