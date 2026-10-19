# RC1 corresponding-source candidate

This is a local source-preparation candidate, not a new binary release.
The proposed source identity is `absd-source-rc1`. It must not move the
existing `absd-preview-rc1` binary tag. No publication or byte-for-byte
reproduction is claimed by this document.

## Source and binary identities

| Input | Exact identity |
|---|---|
| Kernel development revision | `d208b61bcd4826181bf9f401551ab620d4eabba0` |
| Platform development revision | `0fada7ed031bd84e3a469e717c1d0be5dbefedd6` |
| Original compiled release ID | `absd-rc1-c12c-20261018t161241z.fvcgzh` |
| Proposed source identity | `absd-source-rc1` |
| Original build public-key file SHA-256 | `3688414e50a00f776a15b542b0c9166f273e41dfded112ff4c2ae190976720c9` |

The original media assembly was `run-candidate12c-preview.sh` at steward
runner revision `d8471cdc`. Its private coordination, paths and transcripts
are not included. The commands below and `tools/rebuild-rc1.sh` preserve
the build operations, with explicit differences described here.

`SOURCE-MANIFEST.toml` names each original commit and tree, exclusions,
the unchanged filtered tree, every sanitation edit's before/after SHA-256,
and the final public component tree. `tools/assembly.toml` carries the
exact edited line numbers, line hashes and public replacements. The edits
remove private references from comments and test metadata, and replace
unavailable private fixture defaults with nonexistent public placeholders.
One additional recorded build-tool edit adds Python cache-isolation flags
to the media builder's child interpreter. The release-manifest CLI accepts
lineage from explicit --components or ABSD_COMPONENTS_TOML only: its private
sibling-directory fallback is removed. Unset lineage remains absent, as it
already was in a public checkout without that sibling. This host-tool
adaptation changes no compiled artifact or service runtime algorithm. Development
records and other projects' source/patches are excluded explicitly. This
is a curated tree; it is not an identical archive of either development
commit, and it carries no private development history.

The exclusions retain tracked check inputs discovered from literal Python
Path expressions, Rust include_str!/include_bytes! spellings, and
@relative-file fields in TSV fixtures. Assembly follows those references
to a fixed point before extraction and records the restored files in each
component's `keep` list. This includes the health and network-status golden
vectors and capacity/agent check fixtures. `tools/check_inputs.py` repeats
the discovery on the committed public tree and refuses a missing or
untracked input; `tools/check.sh` runs it before the suites. It never imports
component code. This is a bounded omission check, not complete dependency
discovery: dynamic paths, generated inputs, other languages and external
tool requirements still need the real build and qualification suites.

The generic `platform/integration/user-linker.ld` is explicitly retained
because the core ABI-facts checker reads it as well. Retaining that linker
does not include the extended integration programs or their dependencies.

The same preflight checks retained literal `$root/file` pins in the shell
verifier. Curation of the SSH Cargo manifest removes a comment, so its full
file digest differs from the development input. A separate hash-bound edit
updates only that first-party expectation in `verify-inputs.sh`, from the
declared original bytes to the declared curated bytes. The verifier's
comparison and failure behavior, toolchain/upstream pins, locked graphs and
historical reference digests remain unchanged. A mismatched retained literal
pin now refuses assembly before publication. Computed/aggregate and external
pins remain subject to the unchanged checks in the actual input verifier.

Published Markdown, code comments, docstrings and CLI help replace internal
tracker links and project-board identifiers with neutral wording. These
edits have exact input, line and output hashes. The detector checks all
files and refuses any coordination-pattern finding; configuration cannot
waive it. The detector constructs its own repository-name pattern from
separate words so the checking tool does not report its own literal needle.
Existing run UUIDs, provider names, fixture capture fields and functional
refusal/detection needles are retained.

## Prerequisites and public inputs

Use an Ubuntu 24.04 x86-64 machine. Install the packages listed by
`tools/Containerfile`; its versions mirror the media profile. Container
execution is optional. Builds must run as an unprivileged user. The media
tool requires `setarch -R` and the pinned GRUB tools; a restricted
container can refuse that operation. The disposable-VM rebuild is a
separate qualification, not a prerequisite satisfied by this source
assembly.

The authoritative media package and kernel-compiler pins are in
`platform/media/vm-operator.toml`. Both Rust toolchains are required:
**1.98.0 for the kernel, 1.95.0 for the platform**, with rust-src. The
platform's `platform/scripts/verify-inputs.sh` checks compiler, Cargo,
library-source and groff-macro digests. Clang/LLVM 18.1.3 and groff-base
1.23.0 were used. Rust 1.94.0 is for a qualification reference workload,
not the media build. A package version disappearing from public mirrors
is an explicit input-availability failure; do not substitute a newer
version and call it the same build. The base Ubuntu image, Python and
every host library are not fully digest-pinned.

Install both bare-metal ARM64 targets for the kernel's default `make check`
path; its user and kernel builds use different targets. The container recipe
does this too:

```sh
rustup toolchain install 1.95.0 1.98.0 1.94.0 --profile minimal \
  --component rust-src --component rustfmt --component clippy
rustup target add --toolchain 1.98.0 aarch64-unknown-none aarch64-unknown-none-softfloat
```

The kernel framebuffer check also needs `xfonts-base`, which supplies
`/usr/share/fonts/X11/misc/8x13-ISO8859-1.pcf.gz`. Its host oracle reads
the X11 misc-fixed font independently of the kernel's committed glyph
table. This package does not supply GRUB's GNU Unifont boot font or add
a new font to the media. The existing font provenance is recorded in
`kernel/provenance.toml`.

These targets are check prerequisites, not inputs to the x86-64 RC1 media
build. The original media producer's retained tool inventory does not record
its installed Rust target set; it did not run the full kernel check suite.

All inputs needed by the following recipe are first-party source here,
public Rust toolchains, public crates, or publicly downloadable archives:

- Crate checksums and locked dependency graphs: every included Cargo.lock,
  `platform/compat/programs.tsv`, and the stage scripts/patches/locks.
  `tools/fetch.sh` stages the patched standard library, SSH and compatibility
  crates and fetches registry index entries. It reports unused workspaces
  whose fetch failed; any dependency actually missing must fail the offline
  build by name. A fetch report alone is not a successful offline build.
- C kit: `platform/c/picolibc/PIN`, options, cross file and first-party
  adapter sources. The source tarball and exact Meson/Ninja wheels are
  fetched and SHA-256 checked. No private C-kit build tree is an input.
- Installed C commands: `platform/userland/PIN`, `platform/userland/patches/`,
  the Toybox adaptation sources and hashes, and `platform/userland/PORTS.tsv`.
  Source archives come from their public publishers. Their license texts
  and ABSD adaptations remain included.
- Initial authorized-keys input: `docs/rc1/build-authorized-keys.pub` is the
  original **public** build key. Its private half was retired; it is not
  included or needed. This key is for raw-byte reconstruction only.
- Notices input: the original public RC1 notices archive is fetched by
  its published SHA-256. `tools/rc1_notices.py` checks its 370 files and
  the source/supplement inventory before building. It supplies no original
  executable to the compilation or media path.

No private dependency is intentionally required by this media recipe.
Other-project integration workloads are excluded from the public core
profile and cannot be run here. Historical qualification inputs are not
shipped: the S4 comparison and U1-b reference-image cases in media/helper
host tests skip unless their existing environment overrides name such an
input. Their new default paths deliberately do not exist. The preserved
tests do not thereby become qualified.

## Run the reconstruction attempt

Clone the proposed source commit first. The adapter requires Git objects
for its final component trees and a committed, unchanged component source.
Do not run from an uncommitted copied directory. Use a new work directory
outside the source checkout; it owns all derived C-build and media outputs.
Its absolute path must use letters, digits, `_`, `-`, `.` and `/` only.

```sh
tools/rebuild-rc1.sh fetch /absolute/path/rc1-work
tools/rebuild-rc1.sh build /absolute/path/rc1-work
```

For the documented suites, pass that same work directory explicitly after
fetching. The default mode runs kernel and platform checks:

```sh
tools/check.sh all /absolute/path/rc1-work
```

This binds the Picolibc install, pinned venv, C kit, C ports and userland
inputs/outputs to the same paths as the reconstruction recipe, requests
offline Cargo, and gives check helpers a fresh Python launcher before the
venv's Ninja. The core file-server recovery fixture keeps its logs under
`RC1_WORK/core-fsd-recovery`, outside the manifest-verified source tree.
Its existing permission checks, key retirement and verdicts are unchanged.
Without the optional second argument, the generic wrapper
retains the component defaults; it does not consume the RC1 work directory.
Neither mode replaces the frozen platform gate or relaxes its checks.
Do not run the suites concurrently with reconstruction in the same source
or work directory: both build platform outputs. Capture rebuilt ELF/media
artifacts and hashes before running the platform gate, whose ordinary
cleanup may remove earlier build outputs.

The fetch phase is the network phase. C sources/wheels go into that work
directory; Rust crates/index entries go into CARGO_HOME (default ~/.cargo).
The build phase requests offline Cargo and reuses those verified inputs.
Its PATH puts the fresh Python launcher first, then the work directory's
Picolibc venv bin directory. After bootstrap this lets Meson setup find the
pinned Ninja wheel; later build/install steps use that same venv. No host
Ninja installation is substituted.
The release ID remains set for the first-party platform and media build.
The C kit is built with `ABSD_RELEASE_ID` absent, matching the development
identity compiled into the frozen C-port catalog. This reconstructs the
catalog's inputs rather than changing its expected executable digests;
the C-port installation checks remain unchanged.
For enforced network isolation, disable network access for the build phase
at the VM boundary. Source-only preparation has not exercised that claim.
Record command status and full logs; a failed or interrupted attempt is
not a pass. The script refuses an existing media/kernel build attempt,
rather than deleting its evidence. It is an ordinary foreground command;
an unattended qualification needs its operator's durable execution and
recovery checkpoint.

The original effective environment was:

```sh
export ABSD_KERNEL_COMMIT=d208b61bcd4826181bf9f401551ab620d4eabba0
export ABSD_RELEASE_ID=absd-rc1-c12c-20261018t161241z.fvcgzh
export ABSD_PROFILE=core ABSD_CARGO_LOCKED=--locked MAKEFLAGS=-j4
export CARGO_BUILD_JOBS=4 LC_ALL=C
```

`platform/scripts/check-all.sh` still has the older `aee59ea4` default.
The actual RC1 runner exported the exact kernel revision above. The public
recipe and `tools/check.sh` select the manifest pair explicitly; the frozen
component default has not been silently rewritten. Assembly pin checks
inspect the effective public recipe.

With P as the built platform, K as the disposable kernel for the operator
ISO, K2 as a separate disposable kernel for auxiliary boots, PUB as the
included public build key, and OUT as a new media directory, the original
media commands were:

```sh
ABSD_RELEASE_ID=$RID sh "$P/scripts/prepare-and-build.sh"
python3 "$P/scripts/media.py" operator-image --profile vm-operator \
  --platform-tree "$P" --kernel-run "$K" \
  --kernel-commit "$KC" --platform-commit "$PC" \
  --authorized-keys "$PUB" --release-id "$RID" --out "$OUT"
python3 "$P/scripts/media.py" operator-validate --profile vm-operator \
  --platform-tree "$P" --kernel-run "$K" --out "$OUT"
python3 "$P/scripts/enroll-matrix.py" --kernel "$K2" \
  --importer "$P/fixture-import.elf" --enroll "$P/absd-enroll.elf" --work "$ENROLL"
```

These original `media.py` commands require private Git checkouts at KC/PC.
The public recipe calls `tools/rc1_media.py` instead. This RC1-only adapter
verifies the final source-manifest trees, checks source bytes, executable
modes and symlinks directly against Git objects (ignoring local Git filters
and excludes), and substitutes only the checkout checks,
component-tree binding reads and original platform commit epoch. Package
pins, compiler environment, actual compilation, importer boots, deterministic
ISO builder, two-ISO comparison and operator validation retain their frozen
algorithms. The public recipe uses a fresh Python bytecode-cache prefix and
disables cache writes, including for helpers invoked with `-I`. The one-line
media tool adaptation applies these flags to its absolute `/usr/bin/python3`
child. Source-tree bytecode caches are refused: `-B` alone would still read
them. `PUBLIC-SOURCE-ADAPTER.json` explicitly records the curated
trees and original revision identities. No original Git commit is forged.
The receipt's binding trees are the public source trees, so the full receipt
is expected to differ from the private build receipt even if ISO bytes match.

## Known differences and comparison criteria

The original preview **copied ports from the completed candidate chain**
and checked the C catalog, rather than rebuilding them in the media run.
Those private build artifacts are not a public-source input. The public
recipe builds Picolibc, the C kit, C commands and Rust ports from the pinned
public inputs. Port correspondence is not yet established. In particular,
the original runner noted a uucore registry-neighbor concern; the frozen
build-ports script creates fresh per-port Cargo homes. Preserve any resulting
catalog refusal or binary difference and determine its cause. Do not change
catalog hashes to make this reconstruction pass.

After operator validation, `tools/rc1_blank.py` copies the keyed disk and
performs the original ordinary importer step 4 to replace authorized_keys
with empty bytes. It checks filesystem identity and all other file contents,
and records the advancing commit sequence and public-key residue offsets.
Copy-on-write leaves the original public key in unreferenced sectors. The
original public input is included for that reason; generating a new key
would change raw disk bytes. The blank output must have no active login
key and no host seed. No private key is generated by the recipe.

Compare the outputs without normalizing away differences:

| Artifact | Published SHA-256 | Bytes |
|---|---|---:|
| operator ISO | `d1181d465f9dcbc1322087e5c3e2235ac48007c081d7f150494436ae7d30ecef` | 21977088 |
| raw blank disk | `c9913d3bb889ddaffb223e77ac3d8c8c8bb222144ee349068cba79044bc25a78` | 67108864 |
| enrollment ISO | `7251c6262cf3ad311c12bff09a0cfe94f59d8986c38041d50e59b43a63340b7f` | 21043200 |

The original disk was xz-compressed with preset 6. Compare the raw disk,
its active filesystem contents/identity and unreferenced-sector differences
before compression. The enrollment matrix uses wall-clock-stamped
grub-mkrescue, so compare its actual file inventory, kernel payload and boot
configuration as well as recording the unequal-or-equal full digest. This
source work does not change that older path into a deterministic one.
Do not equate structural comparison with byte equality. Rebuilding the
release documentation, checksum file or notices archive is a separate
publication task; the recipe stops at the three media artifacts.

## Licensing, qualification and state-transfer scope

The kernel Intel I219 driver carries its Intel BSD-3-Clause notice and
provenance rule; the kernel license text is included. RC1's already
published third-party notices archive also carries the Intel notice.
That archive omitted Picolibc and the cited `if_em.c` BSD-2-Clause notice,
and carried libm's general copyright summary without its per-file Sun
permission block. `docs/rc1/notices/` supplies an additive correction and
an explicit C-link-input inventory. The complete Picolibc copyright
aggregate includes additional unbuilt files; it is not a statement that
every listed license applies to the shipped binaries. The exact 12 C-port
maps reproduce both unstripped and stripped catalog identities and select
Picolibc libc.a members (including libm_common classification helpers),
with no selected libm.a or libclang_rt.builtins archive members.
The Rust libm notices are a separate input. See TEXT-PROVENANCE.json and
C-LINK-CORRESPONDENCE.json for the evidence and its limits.

The checker binds the frozen C driver, userland catalog/build inputs and
driver attribution source by hash; an input change requires a fresh audit.
It refuses unclassified C archives, missing/changed texts or a different
base archive. This complements the existing Rust and boot inventories; it
does not infer arbitrary source derivation or prove compiler/linker behavior.
Run it as a release check and package the proposed correction separately:

```sh
python3 -B tools/rc1_notices.py check --base /path/to/absd-rc1-third-party-notices.tar.gz
python3 -B tools/rc1_notices.py package --base /path/to/absd-rc1-third-party-notices.tar.gz \
  --out /path/to/absd-rc1-third-party-notices-correction-1.tar.gz
```

The package is deterministic and additive. Existing assets stay unchanged;
the corrective asset's publication remains a separate owner decision.
The website wording condition is explicitly answered by the deployed
public-site source revision `58126fb07ca19b919ef7e668790cfc7faa8dfcaa`
(gh-pages `4492679`, verified at 2026-10-18T22:10:27Z). The about page now
names the I219 derivation and its Intel notice. This recorded deployment
evidence closes that condition; it does not establish a guest rebuild.
The xHCI legacy masks retain their adjacent xHCI 1.2 specification citations.
The published RC1 boot corresponding-source archive supplies the exact
GRUB and GNU Unifont source; consult the binary release's NOTICES.md.
This first-party source candidate does not replace that archive or relicense
the boot components. See the generated THIRD-PARTY.md and LICENSING.md.

Source-tree correspondence is checked by exact Git identities, file/line
SHA-256 preconditions and two independent assemblies. Bounded model checking
would not establish that arbitrary build tools reproduce these binaries;
practical deterministic source checks and independent clean-room execution
are the appropriate evidence here. The assembly owner records exact receipt
identities; the independent reviewer decides acceptance. Model limits:
no compiler correctness, hardware behavior or source-to-binary theorem.

This source-only packaging changes no running kernel, authority contract
or replacement state schema. It transfers no live handles or reservations.
It supplies no quiescence, fencing, migration, rollback or generation-retirement
mechanism. The existing ABSD live-evolution constraints still apply to any
future integration of the source it contains.

## TinyCC stage excluded from this public source

TinyCC compiler qualification is NOT_RUN / not included in the public
source. The three patch files contain copied upstream context as well as
locally introduced ABSD changes; they are omitted. The generated target
configuration is also omitted. The five locally introduced build-support
files are omitted because they have no consumer outside that unavailable
stage, not because their text was found to be LGPL-derived.

The public staging, build, run, array-receipt and compiler-fixture self-test
entry points return status 78 with `TCC STAGE NOT_RUN: not included in the
public source`. Cached products and skip-build settings do not bypass this
public CLI refusal. Judging-helper imports and their independent host unit
tests are separate from compiler qualification. Historical TinyCC details
in C-INTERFACE.md describe the private stage, not a reproducible public
stage. No replacement compiler is included or claimed qualified.

The public check wrapper prints this omitted-stage status. TinyCC was not
on the RC1 media recipe or core gate path; both kernel and core checks keep
their original criteria. A core PASS does not include TinyCC or the excluded
extended other-project profile. The source manifest records both as not
run. See platform/docs/PROVENANCE.md for the owner's distribution policy.
