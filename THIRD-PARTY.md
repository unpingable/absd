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
| `kernel/src/i219.rs` | adapted | BSD-3-Clause | BSD-3-Clause | Intel e1000 shared code as carried in FreeBSD sys/dev/e1000 (e1000_ich8lan.c, e1000_phy.c, if_em.c) at revision 833d39bd2e38421a14ea489a956261a0fa993fbc |

## `platform/`

| Path | Class | Licence | Upstream licence | Upstream |
|---|---|---|---|---|
| `platform/c/vectors/startup/*.bin`<br>`platform/c/vectors/startup/*.json` | generated | Apache-2.0 |  |  |
| `platform/cports/demand/*.undef.txt`<br>`platform/cports/demand/*.residual.txt` | generated | Apache-2.0 |  |  |
| `platform/userland/DEMAND.tsv`<br>`platform/userland/DEMAND-SUMMARY.tsv` | generated | Apache-2.0 |  |  |
| `platform/cxx/llvm-project.LICENSE` | imported | Apache-2.0 WITH LLVM-exception |  | llvm-project 18.1.8 (cxx/PIN), LICENSE.TXT |
| `platform/cxx/patches/llvm/*.patch` | adapted | Apache-2.0 WITH LLVM-exception | Apache-2.0 WITH LLVM-exception | llvm-project 18.1.8 (cxx/PIN): libcxx/src, llvm/lib/Support, llvm/lib/TargetParser, llvm/lib/Passes, clang/lib/Frontend, lld |
| `platform/cxx/glue/llvm-support/*.inc` | adapted | Apache-2.0 WITH LLVM-exception | Apache-2.0 WITH LLVM-exception | llvm-project 18.1.8 (cxx/PIN): llvm/lib/Support/Unix/{Signals,Program,Memory,Watchdog}.inc |
| `platform/cports/demand/picolibc-1.8.12-defined.txt` | generated | Apache-2.0 | BSD-3-Clause | picolibc 1.8.12 (symbol names only, from its built archives) |
| `platform/Cargo.lock`<br>`platform/**/Cargo.lock`<br>`platform/pins/**` | generated | Apache-2.0 |  |  |
| `platform/provenance/inventory/**`<br>`platform/provenance/baseline/**` | generated | Apache-2.0 |  |  |
| `platform/patches/rust-1.95.0-absd-std.patch` | adapted | Apache-2.0 | MIT OR Apache-2.0 | rust-lang/rust 1.95.0, library/ (the pinned rust-src component); ABSD std-mtime 2026-10-17 adds first-party V2 metadata-hook forwarding and whole-second modified() presentation, preserving upstream notices and terms |
| `platform/patches/sunset-server-channel.patch` | adapted | Apache-2.0 | 0BSD | sunset 0.6.0 (crates.io archive) |
| `platform/patches/ring-absd.patch` | adapted | Apache-2.0 | Apache-2.0 AND ISC | ring 0.17.14 (crates.io archive), build.rs |
| `platform/observe/served.rs` | adapted | Apache-2.0 | Apache-2.0 | constellation-monitor public cut at 81c2354 (the owner's project) |
| `platform/userland/sbase.LICENSE` | imported | MIT |  | sbase 0.1 (userland/PIN), LICENSE |
| `platform/userland/patches/*.patch` | adapted | Apache-2.0 | MIT | sbase 0.1 (userland/PIN): the utility sources each patch names |
| `platform/userland/diff/diff.c`<br>`platform/userland/diff/diff.patch` | adapted | Apache-2.0 | 0BSD | Toybox 0.8.15 toys/pending/diff.c; tag a57b091d05ec366dcd4dd737784c03761cb6a4b1; archive SHA256 44e2bab43dfe2c171743297631ce558c6d9ed38b87a66fd751cef617574b375e (userland/diff/SOURCE.json) |
| `platform/userland/diff/LICENSE` | imported | 0BSD |  | Toybox 0.8.15 LICENSE, verbatim; archive SHA256 44e2bab43dfe2c171743297631ce558c6d9ed38b87a66fd751cef617574b375e (userland/diff/SOURCE.json) |
| `platform/vendor/tempfile/**` | imported | MIT OR Apache-2.0 |  | tempfile 3.27.0 (crates.io archive, vcs sha1 5c8fa12e) |
| `platform/vendor/tempfile/src/file/imp/mod.rs`<br>`platform/vendor/tempfile/src/lib.rs` | imported | MIT OR Apache-2.0 |  | tempfile 3.27.0, with three ABSD lines (vendor/README.md) |
| `platform/vendor/rustc-literal-escaper/**` | imported | MIT OR Apache-2.0 |  | rust-lang/literal-escaper v0.0.5 as embedded in proc-macro2 1.0.106 (src/rustc_literal_escaper.rs, src/num.rs) |
| `platform/vendor/rustc-literal-escaper/src/lib.rs`<br>`platform/vendor/rustc-literal-escaper/Cargo.toml` | imported | MIT OR Apache-2.0 |  | as above; lib.rs gains four ABSD lines and the manifest is rewritten for the std workspace (vendor/README.md) |
| `platform/userland/hexdump/hexdump.c`<br>`platform/userland/hexdump/hexdump.patch` | adapted | 0BSD | 0BSD | Toybox 0.8.15 toys/pending/hexdump.c; archive and member SHA256 in userland/hexdump/SOURCE.json |
| `platform/userland/hexdump/LICENSE` | imported | 0BSD |  | Toybox 0.8.15 LICENSE; exact archive member SHA256 in userland/hexdump/SOURCE.json |
| `platform/man/toybox.7` | adapted | Apache-2.0 | 0BSD | Toybox 0.8.15 LICENSE, copied in its LICENSE section |
| `platform/userland/patches/tar-absd.patch` | adapted | MIT | MIT | sbase 0.1 tar.c; archive pinned in userland/PIN |
| `platform/userland/tar-vectors/basic.ustar` | generated | Apache-2.0 |  |  |
| `platform/patches/ring-absd-tls-fixture-rng.patch` | adapted | Apache-2.0 | Apache-2.0 AND ISC | ring 0.17.14 (tls/PIN.json), src/rand.rs |
