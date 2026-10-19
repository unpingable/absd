# Unchanged-source Markdown application fixture

S3 in coordination tranche #24, from accepted-with-limits platform
`bf8c7583b830ccab0982cf36b336086912a0a900` and unchanged kernel
`f8184cae7dd6a097f47331fb763c2f5fdae770cc`. This is a separate development
fixture, not an amendment to the canonical compatibility qualification gate.
The twelve refreshed C ports and their catalog hashes remain the base.

Independently selected application: the upstream **pulldown-cmark 0.13.4 CLI**,
default features (`getopts`, `html`). It converts Markdown files or stdin to
HTML, including Unicode, code blocks and optional tables/task lists. This is
useful for documentation conversion and exercises a real published application's
argument parsing, filesystem reads, pipes, buffered output and error exits.
Selection was based on that use, not on adding another port to a count.
It does not exercise networking, threads, process creation inside the application
or writable files. A result here supports only those consumed facilities.

## Reproduce on a Linux development host

Use the repository's pinned Rust 1.95.0, upstream rust-src, LLVM 18 strip and
existing offline crate inputs. `scripts/verify-inputs.sh` and
`scripts/stage-library.sh` validate the existing compiler/library pins. The
application archive is pinned by registry SHA-256 in `prepare.py`; the published
upstream lock's 23 package identities are preserved, with 15 additions for the
runtime closure. No feature is disabled and no dependency is substituted.
The application and all its dependency sources remain unchanged. The native
helper forces release panic=abort, LTO, opt-level z, one codegen unit and std
optimize_for_size. The Linux reference uses upstream release settings.

Set `APP_STAGE` to a fresh source directory and `APP_OUTPUT` to a fresh build
directory on the configured, verified bulk storage. Check the shared host's
capacity/reserve and coordinate any compiler/guest slot before allocation.
These variable names are examples, not preconfigured paths. The build script
refuses to reuse an output directory and never deletes shared compatibility
staging, SDK files or compiler outputs.

```sh
export ABSD_PROFILE=core
scripts/stage-library.sh
python3 compat/native-markdown/prepare.py --stage "$APP_STAGE"
scripts/build-native-app.sh \
  "$APP_STAGE/absd/pulldown-cmark-0.13.4/Cargo.toml" \
  pulldown-cmark "$APP_OUTPUT"
python3 compat/native-markdown/prepare.py --stage "$APP_STAGE" --check
(cd "$APP_STAGE/linux/pulldown-cmark-0.13.4" && \
 env -u RUSTFLAGS -u CARGO_ENCODED_RUSTFLAGS -u RUSTC -u RUSTC_WRAPPER \
  -u RUSTC_WORKSPACE_WRAPPER GIT_CEILING_DIRECTORIES="$APP_STAGE" \
  CARGO_TARGET_DIR="$LINUX_OUTPUT" \
  cargo +1.95.0 build --release --offline --locked \
  --manifest-path "$APP_STAGE/linux/pulldown-cmark-0.13.4/Cargo.toml" \
  --bin pulldown-cmark)
```

The cache needs `pulldown-cmark-0.13.4.crate`, `getopts-0.2.24.crate` and
`pulldown-cmark-escape-0.11.0.crate` as well as the locked dependencies. Fetch
missing crates separately from static.crates.io and verify against the lock's
registry checksums before the offline build. `--cache` lets the source check
use a private cache; `CARGO_HOME` supplies Cargo's own cache location.

`prepare.py` extracts the published archive twice. Only the ABSD-only
`absd-runtime` dependency stanza and additive Cargo.lock differ. The existing
wrapper injects experimental `restricted_std` and forces runtime linkage; this
is experimental target scaffolding, not an application patch or a stable SDK
promise. The new build helper reuses that mechanism for one external Cargo
application with its own build directory. It does not install an application,
resolve components or modify a release catalog. Output includes a stripped
native ELF, an unstripped ELF for host-side inspection, compiler identity and
input/output digests. It does not verify source identity itself; run the source
checker separately. Cargo configuration and path dependencies must also be
identified for a new run. Rerun the source check after compiling.

## Native execution

Use an isolated, disposable kernel **run clone** at `f8184ca` and the accepted
base's `fixture-import.elf` and `compat-launch.elf` (or rebuild those two bins
at the exact platform source). Record their actual hashes. Never mutate the
protected kernel checkout, a U1 image or the steward's build directories.
In fresh command directories place `$APP_OUTPUT/pulldown-cmark` and the Linux
binary respectively. With the fixture's committed `expected.txt`, run:

```sh
python3 scripts/compat-matrix.py --kernel "$KERNEL_RUN" \
  --importer "$IMPORTER" --launcher "$LAUNCHER" \
  --commands "$APP_COMMANDS" --linux "$LINUX_COMMANDS" \
  --compat compat/native-markdown --expected compat/native-markdown/expected.txt \
  --work "$GUEST_OUTPUT" --qemu "$ABSD_QEMU"
```

The existing matrix imports and reads back exact program/input bytes, starts
each application from the native filesystem with `Command`/`spawn_image`,
compares stdout/stderr/exit against Linux and the committed reference, verifies
the kernel spawn count and requires terminal zero resource accounting. The
new fixture covers file and piped input, Unicode, extensions, events, help,
empty stdin in event mode (`-e`), multiple file arguments, invalid options and rejected broken
links. No divergence is permitted in these selected cases. A native run needs
the steward's guest admission; successful host compilation alone proves none
of this behavior.

## Boundaries and formalization consideration

This is **cross-development**: Linux executes Cargo/rustc/linker and builds an
ABSD executable. ABSD executes the application. No compiler or Cargo runs on
ABSD, and neither Userland U4's deferred component/admission closure nor U5/U6
is activated. System R4 and the kernel repository's `docs/application-interface-v0/README.md`
and `docs/USERLAND-COMPONENT-ROADMAP.md` and the platform compatibility ledger own
the roadmap and interface boundaries. No whole R4, U1, release, POSIX or Linux
ABI acceptance follows.

Proposition: for the identified archive, additive lock/runtime scaffolding and
these finite inputs, application source is unchanged and the native execution
agrees byte for byte with the Linux reference, including error status. Exact
source/result identities belong in the execution report. Owner: S3 Codex;
independent acceptance remains the integration steward's responsibility.
Archive/file comparisons and the existing end-to-end matrix are sufficient
for this finite observation; a model would not establish arbitrary Markdown
correctness, capacity behavior, concurrent service replacement or physical
durability. No new authority, state schema, handle lifetime or kernel ABI is
introduced. Any later runtime replacement must separately fence old users,
validate the successor and refuse incompatible state; retained executables
do not prove rollback after externally visible effects.
