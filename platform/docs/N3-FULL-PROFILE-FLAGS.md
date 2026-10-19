# Full-profile source-path flags (bounded N3 follow-on)

`scripts/inputs.sh:absd_full_rustflags` supplies complete, token-delimited
`CARGO_ENCODED_RUSTFLAGS` to the six existing full-profile builders:
integration, Nightshift, Pulse, Pulse observe, NQ and AG loopctl. The existing
`absd_rust_remap` zero-argument helper and its callers are unchanged.

## Contract

Each family retains its existing linker and section-GC flags, cfgs, program
arguments/names, panic/strip variants and SQLite C flags. Integration retains
its workspace-relative linker argument. The five standalone family builders
retain the platform-absolute linker argument. Pulse families retain their
check-cfg and only their test variants enable `pulse_absd_test_config`; other
families retain the `getrandom_backend="rdrand"` cfg.

The flag list remaps logical and physical spellings of the platform to `/absd`,
Cargo registry sources to `/cargo/registry/src`, and seven existing sibling
staging roots to `/absd-inputs/{ag,pulse-source,nightshift,pulse,pulse-observe,nq,ag-loopctl}`.
Duplicate spellings are deduplicated. Conflicting identities for one spelling
are refused. More specific mappings follow broader mappings because rustc uses
the last matching prefix. Relative paths, parent-traversal `..` components, `=` and ASCII control bytes (including
the encoded unit separator) are refused before normalization. In particular,
normalizing a symlink followed by `..` would change its filesystem meaning;
this helper refuses that input instead of choosing an incorrect source identity. Spaces and quotes remain intact Rust
flag tokens; this does **not** extend the existing CFLAGS/staging scripts' path
support. No shell evaluation is applied to these tokens.

Cargo's config arrays concatenate. An observed Cargo 1.95.0 no-build config
probe combined a file array `["BASE"]` and a command-line array `["EXTRA"]` as
`["BASE","EXTRA"]`. Thus using an additional `--config` array is not a complete
replacement for existing flags. Cargo's installed 1.95 documentation specifies
mutually exclusive precedence: encoded flags, RUSTFLAGS, target config arrays,
then build.rustflags. These builders use the complete encoded list, clear the
competing inherited flag variables and wrappers, and add no redundant config
array. Consequently additional rustflags from a local Cargo configuration are
intentionally superseded for these target builds. Future required family flags
must be added explicitly to the helper. Host build-script/proc-macro compiler
flags are outside this target-flag claim.

## Tests and limits

Run `python3 -B scripts/test_full_profile_flags.py`. It executes the actual shell
builders with recording Cargo/clang and staging fixtures, asserts the existing
18 output names across 15 Cargo calls, exact family cfg/C/program options,
standalone calls, ambient-variable clearance, token boundaries, alias handling,
refusals and stage/Cargo failure propagation. Marker files are **not** ELF files.
It checks the unchanged legacy helper independently. No compiler, guest,
network access, upstream source staging or full-profile qualification is run.

This change supplies source-path flags only. It does not establish equal
artifacts across checkout paths. Cargo metadata can still encode outside-
workspace path dependencies; imported C source can still retain paths. The
integration durable workspace relationship and the NQ profile-digest inputs
must remain intact in any separately admitted layout correction. This change
alters no manifests, locks, stage layouts, upstream patches or runtime code.
External tools and other compiler-generated strings are not covered by rustc's
best-effort source remapping. There is no new ABI, live-kernel replacement,
authority transfer or state schema.

Formalization consideration: the bounded proposition is that six existing
builders pass the admitted family-specific target tokens and unchanged output
inventory, or refuse ambiguous helper inputs. Recording execution, literal
expected vectors, negative cases and primary Cargo/rustc precedence documentation
are sufficient for this source-plumbing step. They do not prove compiler behavior
or artifact identity. The engineering controller owns admission of later
comparative qualification; acceptance of this step remains independently reviewed.
