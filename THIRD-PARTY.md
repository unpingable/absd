# Third-party material in this source tree

Generated from each component's `provenance.toml`, which is the record to
correct. It lists files carried in this tree. Libraries fetched at build time
are listed per image in each component's `provenance/inventory/`.

## `kernel/`

| Path | Class | Licence | Upstream licence | Upstream |
|---|---|---|---|---|
| `kernel/Cargo.lock` | generated | Apache-2.0 |  |  |
| `kernel/provenance/inventory/**`<br>`kernel/provenance/baseline/**` | generated | Apache-2.0 |  |  |
| `kernel/fbcon/src/font8x13.rs` | generated | Apache-2.0 | LicenseRef-font-misc-misc-public-domain | X.Org font-misc-misc 8x13-ISO8859-1 (Debian xfonts-base), printable ASCII only |

## `platform/`

| Path | Class | Licence | Upstream licence | Upstream |
|---|---|---|---|---|
| `platform/Cargo.lock`<br>`platform/**/Cargo.lock`<br>`platform/pins/**` | generated | Apache-2.0 |  |  |
| `platform/provenance/inventory/**`<br>`platform/provenance/baseline/**` | generated | Apache-2.0 |  |  |
| `platform/patches/rust-1.95.0-absd-std.patch` | adapted | Apache-2.0 | MIT OR Apache-2.0 | rust-lang/rust 1.95.0, library/ (the pinned rust-src component) |
| `platform/patches/sunset-server-channel.patch` | adapted | Apache-2.0 | 0BSD | sunset 0.6.0 (crates.io archive) |
| `platform/patches/ring-absd.patch` | adapted | Apache-2.0 | Apache-2.0 AND ISC | ring 0.17.14 (crates.io archive), build.rs |
| `platform/vendor/tempfile/**` | imported | MIT OR Apache-2.0 |  | tempfile 3.27.0 (crates.io archive, vcs sha1 5c8fa12e) |
| `platform/vendor/tempfile/src/file/imp/mod.rs`<br>`platform/vendor/tempfile/src/lib.rs` | imported | MIT OR Apache-2.0 |  | tempfile 3.27.0, with three ABSD lines (vendor/README.md) |
| `platform/vendor/rustc-literal-escaper/**` | imported | MIT OR Apache-2.0 |  | rust-lang/literal-escaper v0.0.5 as embedded in proc-macro2 1.0.106 (src/rustc_literal_escaper.rs, src/num.rs) |
| `platform/vendor/rustc-literal-escaper/src/lib.rs`<br>`platform/vendor/rustc-literal-escaper/Cargo.toml` | imported | MIT OR Apache-2.0 |  | as above; lib.rs gains four ABSD lines and the manifest is rewritten for the std workspace (vendor/README.md) |
