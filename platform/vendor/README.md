# Vendored crates

Origin, licence and local changes for each directory here. The six
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

Everything else is byte-identical to the archive. The ABSD lines and `absd.rs` are first-party Apache-2.0, as recorded in `provenance.toml`.

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
standard-library workspace. Those ABSD changes are first-party Apache-2.0, as recorded in `provenance.toml`.

Build-only: `scripts/stage-library.sh` copies it into the staged library as
`proc_macro`'s dependency.

## ctrlc-stub, nix-absd

Not vendored upstream code. Each is a first-party crate that takes the name
and version of the crate it substitutes for and contains none of its source.
Their manifests used to carry the substituted crate's licence string (`MIT OR
Apache-2.0`, `MIT`), written with the stub and never an owner decision; the
owner had the fields removed on 2026-10-10. `provenance.toml` lists both as
first-party Apache-2.0.

<!-- REUSE-IgnoreEnd -->

## Native shell parser and filename patterns

`conch-parser` is the established Rust shell grammar/AST from
https://github.com/ipetkov/conch-parser, crates.io 0.1.1 archive SHA256
`baf61cea7edff80a7d8a9a4c219d391664715559e9d4e7129494b45278705a41`.
It is MIT OR Apache-2.0; both upstream licence texts and the upstream README
are retained. ABSD evaluates this AST with native process handles; the
upstream Unix shell language grammar does not promise Unix runtime semantics.
Only src/, Cargo.toml, README.md and both licence files are included.

Small adaptations: the manifest normalizes upstream's legacy `MIT/Apache-2.0`
spelling to the equivalent SPDX expression `MIT OR Apache-2.0`, explicitly records edition 2015 and allows
obsolete upstream warning lints; the two case-parser error macros lose a
trailing semicolon rejected by current Rust. The dependency on void 1 is
replaced by std::convert::Infallible in both builders, two closure Ok values
have an explicit error type, and the unused extern crate declaration is
removed. This avoids carrying a separate obsolete type crate (whose 1.0.2
archive does not contain a licence text). No new grammar or parser is written.
ABSD manifest/compatibility changes are first-party Apache-2.0.

ABSD also requires an explicit heredoc delimiter at EOF. The local
`parse/mod.rs` adaptation returns `UnterminatedHeredoc` with the delimiter and
body position instead of accepting an EOF-terminated body. Interactive input
can continue collecting; scripts and `-c` refuse before execution. A delimiter
that is the final line without a trailing newline remains valid. The upstream
MIT and Apache-2.0 notices are unchanged.
The additional local adaptation strips tabs only at the start of each line,
preserving interior and trailing tabs. The EOF error also carries the parser's
normalized delimiter and tab mode so prompt collection can skip full reparsing
of non-delimiter body lines. Unquoted backslash-newline pairs are removed
before delimiter comparison, preserving backslash parity and tabs after a
joined nonempty prefix. Quoted delimiters keep body bytes literal. Delimiter
comparison no longer accepts an extra carriage return; `lexer.rs` keeps CR
as a literal word byte rather than whitespace, including in delimiter headers.
Terminal CR translation remains outside the parser. Other body escape
interpretation stays in ABSD's evaluator; the grammar and AST remain conch's.

`shell-glob` contains glob 0.3.3 (MIT OR Apache-2.0), archive SHA256
`0cc23270f6e1808e30a928bdc84dea0b9b4136a8bc82338574f23baf47bbd280`.
Its src/ and both upstream licence files are unchanged; the manifest adds
explicit edition 2015 and the same warning lint settings. Both crates are
path dependencies of the production root package and the standalone sh
host-test package, and are content-pinned in scripts/verify-inputs.sh.
