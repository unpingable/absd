# RC1 corresponding-source candidate

This is a local source-preparation candidate, not a new binary release.
The proposed source identity is `absd-source-rc1`. It must not move the
existing `absd-preview-rc1` binary tag. No publication is claimed here. The qualification below distinguishes exact
executable correspondence from unequal media bytes; it does not promise
whole-media byte equality.

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
public inputs. The frozen build-ports script creates fresh per-port Cargo
homes, so uucore's registry-neighbor locale inputs are isolated. The remaining
platform/sysroot path dependency and its controlled result are described
below. Do not change catalog hashes to make a reconstruction pass.

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

## Recorded build-root dependency and executable hashes

The eight Rust ports are `basename`, `seq`, `cut`, `fold`, `nl`, `uniq`,
`base64` and `rg`. Their frozen `build-ports.sh` remaps each private Cargo
home, but omits the platform and staged-library path remaps used by
`prepare-and-build.sh`. Absolute Rust source paths therefore enter the
stripped ELF's location records and affect read-only data, layout and code
generation. This is a compiled-byte dependency, not merely a debug-path
change. A different root can change bytes even when the total file size
stays the same.

The original platform root was:

```text
/data/git/absd/.campaign-local/absd-rust-std-steward-candidate12c-20261017
```

Its sysroot and Rust library source were, respectively:

```text
/data/git/absd/.campaign-local/absd-rust-std-steward-candidate12c-20261017/.staged-sysroot
/data/git/absd/.campaign-local/absd-rust-std-steward-candidate12c-20261017/.staged-sysroot/lib/rustlib/src/rust/library
```

The compatibility stage was the sibling
`/data/git/absd/.campaign-local/absd-std-staged-compat`.

A controlled host rebuild of the public component source at these exact
paths produced all eight complete published ELF files byte for byte. It
used the unchanged scripts and pinned inputs and took 254 seconds on four
CPUs. Thus the published eight-port bytes are reproducible from this
source at the recorded roots. The separate fresh-VM rebuild at another
root retained its original unequal-byte result; no output was normalized
or expected digest changed. Independent result review is recorded with
the release evidence. This is one qualified input/path combination, not
compiler correctness or arbitrary-environment reproducibility.

The guest checks and supplemental reconstruction used source revision
`41f5a1baec603b68206df59cc200954c300c143d`. The subsequent public-source
changes affect the check wrapper, this documentation and the manifest
assembler identity, outside the identical kernel/platform component trees. Those later source revisions
were not independently re-executed as guest campaigns.

The supported reconstruction attempt above may use another checkout root.
Expect its eight port hashes to differ; the fresh-VM attempt at
`/home/builder/src/platform` did so. The other 40 named binaries below
(three services, 25 native commands and 12 C ports) matched exactly. All
12 raw C catalog identities also matched. A mismatch in those 40 binaries,
a raw or stripped C catalog refusal, or a Rust-port mismatch when replaying
the qualified recorded paths requires investigation. A successful build
alone does not waive any of these comparisons.

The blank disk contains these ports, so their changed bytes and sizes also
change its filesystem allocation and disk digest. The operator ISO boots
the served system from that separate disk; it does not contain the eight port
ELFs. Its separate kernel-metadata difference is described below. The
enrollment ISO also has independent kernel and packaging differences.
Reproducing the eight port ELFs does not promise equality of all media.

### Replay the eight ports at the recorded paths

First finish the ordinary public `fetch` and `build` recipe above, retaining
its work directory. The commands below reuse only its freshly built,
catalog-checked raw C outputs for the unchanged script's final C-install
step; they do not use any original RC1 executable as a compilation input.
The Rust targets and private Cargo homes are created afresh by the frozen
script. Keep the pinned toolchains, archives and host tools.

Run as the same unprivileged builder. Linux must permit unprivileged user
and mount namespaces and `unshare --keep-caps`. The directory
`/data/git/absd/.campaign-local` must already exist as a directory for the bind mount; on a
new machine an administrator may create that empty directory first.
Do not change an existing checkout there. The two bind mounts below exist
only in the child namespace and leave the host path unchanged. Use a new
scratch directory, four CPUs available to your account, and no concurrent
build against this scratch source. This replay builds ports only, not a
new guest or media set.

```sh
set -eu
export RC1_REPLAY_WORK=/absolute/path/rc1-work
# Choose four available CPUs; the controlled host run used 2-5.
export RC1_REPLAY_CPUS=2-5
source_tree=$(pwd -P)
source_revision=$(git rev-parse HEAD)
export RC1_REPLAY_SOURCE=$(mktemp -d "$HOME/rc1-recorded-root.XXXXXXXX")/source
git clone --no-local --no-hardlinks "$source_tree" "$RC1_REPLAY_SOURCE"
git -C "$RC1_REPLAY_SOURCE" checkout --detach "$source_revision"
mkdir "$RC1_REPLAY_SOURCE/absd-rust-std-steward-candidate12c-20261017"
test -d /data/git/absd/.campaign-local
test -d "$RC1_REPLAY_WORK/userland-build"
case "$RC1_REPLAY_WORK/" in /data/git/absd/.campaign-local/*) exit 1 ;; esac

taskset -c "$RC1_REPLAY_CPUS" nice -n 19 \
  unshare -cm --keep-caps sh <<'REPLAY'
set -eu
mount --make-rprivate /
mount --bind "$RC1_REPLAY_SOURCE" /data/git/absd/.campaign-local
p=/data/git/absd/.campaign-local/absd-rust-std-steward-candidate12c-20261017
mount --bind "$RC1_REPLAY_SOURCE/platform" "$p"
export ABSD_PROFILE=core ABSD_CARGO_LOCKED=--locked CARGO_NET_OFFLINE=true
export CARGO_BUILD_JOBS=4 ABSD_USERLAND_BUILD="$RC1_REPLAY_WORK/userland-build"
sh "$p/scripts/stage-library.sh"
sh "$p/scripts/render-man.sh"
sh "$p/scripts/build-ports.sh"
REPLAY

for name in basename seq cut fold nl uniq base64 rg; do
  sha256sum "$RC1_REPLAY_SOURCE/platform/ports/$name"
done
```

The namespace maps your current nonzero UID to itself. `unshare -rm`
would instead present UID0 to GNU tar, which can then try to restore
archive owner IDs absent from the namespace and refuse before compilation.
Mapping the current UID avoids that archive-ownership failure without
changing source, scripts or compiler flags. The CPU affinity supplies the
four-job bound: the frozen per-port `env -i` intentionally drops an outer
`CARGO_BUILD_JOBS` value. Namespace and tool failures are explicit failed
attempts, not permission to weaken the script or expected hashes.

Stable platform/sysroot remapping and two fresh builds at different roots
are planned for a subsequent release. That change is not part of this
frozen RC1 source and has not established root-independent reproducibility.

The following are complete published ELF hashes, not normalized section
hashes. Paths are relative to the source checkout. Check the eight Rust
rows after recorded-path replay; the other rows apply to the ordinary
pinned public reconstruction as well.

| Kind | Path | Bytes | SHA-256 |
|---|---|---:|---|
| service | `platform/absd-enroll.elf` | 262288 | `05f54a5cece08de7dd4a147205b92bbb51e8aa78fb2ff0f1d99505965e6d4de9` |
| service | `platform/absd-fsd.elf` | 407432 | `339c780442728b3d87209c2357c5c642fe486e8135b9aaa872ccaf606f7746f8` |
| native command | `platform/commands/absd-sh` | 354392 | `afb135822fbf86cbf5b69460ebbb4bd8d3df4db981f3aee0a630d9feee4c2dab` |
| native command | `platform/commands/cat` | 211008 | `95569da2d150342c7d35b77ba1c6e86fb28d61d7bf2656cdaa0cd3f5d84aefdd` |
| native command | `platform/commands/cp` | 260160 | `a61afe6ced381b9d8334b4091a16adc1a2d6968865b3253d48c1a30b49d4345c` |
| native command | `platform/commands/date` | 124928 | `95f918a953b5c158678366dd0364ac3766eab99e812765135d0d5609a395839d` |
| native command | `platform/commands/df` | 124928 | `e76f3622d63013c026d27a9ca1555eb49f4ce1ebc336674406a81056238c1cd0` |
| native command | `platform/commands/echo` | 120832 | `f26de4bbc4b2a06feb9a8134582e3a32668b5986e9f18c0d7b2ca0a537f8525a` |
| native command | `platform/commands/head` | 231488 | `9671c509d03546fdc8847200dd35b15c3da90eb968ee9d2eb3192c329e26b07d` |
| native command | `platform/commands/health` | 292928 | `6757591df27fd9461193773dbb350aef892e1e910d1c14b903b45fe802d3cbb6` |
| native command | `platform/commands/ls` | 161792 | `2bb5cb16e390bf7b26d6bb1ff8743d224a24e8d809eab336a5ee1c1e5ee00424` |
| native command | `platform/commands/man` | 223296 | `8f1e2d222cd56dfe7d53d44959321aa76afb2cf8bbdaf7ebae2ce3367b60e88f` |
| native command | `platform/commands/mkdir` | 161856 | `5f68138b457f0bea78fef9d84591d9cee0628b79c5e8eb2a506fdc2f08a2d784` |
| native command | `platform/commands/mv` | 190528 | `2e83cd938b9d001be7291ecd2aeb724461512986eac72bb7041195e303b26d33` |
| native command | `platform/commands/net-status` | 219200 | `e768a1951897c8bf614dc6cd2f9957590fe26e1425db18f8a938378295b77292` |
| native command | `platform/commands/printenv` | 129024 | `7d26944f729e638c62ddc2d64d342641db3dde59daea304f6ce4971d4ae78074` |
| native command | `platform/commands/pwd` | 120832 | `b5c6b56f2f3fac86ed4f0f7883aa7f93631a7f2e5d2312741b2e01fce7b7ad65` |
| native command | `platform/commands/release` | 120832 | `3ddab1a0d90dc0a49292487431f883dad8fa17a900abda60a4d3f435e85274d5` |
| native command | `platform/commands/rm` | 206912 | `3b902079e2e1a0acfb77f04477a8380815b8e6eb1cd217414b95cb855294be53` |
| native command | `platform/commands/sha256sum` | 223296 | `afc3ad81be5612c92323964c1916c85496c1c07a0edc8e3c64d0e7dfd21e340c` |
| native command | `platform/commands/stat` | 145408 | `26293c389798baa91cef162d134a191189ed34b7c3fa72e5e865368bc3fea550` |
| native command | `platform/commands/sync` | 124928 | `acc72a94e738349cfde68fce5abea999e8367d14ab86034430c4fa4d78b7186b` |
| native command | `platform/commands/sysinfo` | 124928 | `b4a4442f9f45502fdb0342ebc9a5a7f00f95a9747c951305c4c96980aec81963` |
| native command | `platform/commands/tail` | 223296 | `44e78296ba21337c584f51e0ff99e07c295ff911f155d259ccc96593412adcad` |
| native command | `platform/commands/uname` | 124928 | `cc7a7e4a792afc02aff5e4f24026e77ada21f6df9e4802655425bdf32b4a3bfd` |
| native command | `platform/commands/uptime` | 120832 | `ebea82909789fabd45aafcda89926f58c7e26f254c36f308187b52657c69b2da` |
| native command | `platform/commands/wc` | 223296 | `689f76e664aec3c1fe024bff648365fcd8c174d19e56b97fed8425ee04fa9091` |
| Rust port | `platform/ports/base64` | 555216 | `597a031c292fc373b67018335ac8ec431c5bca8a7cbf4a1bedb37047e6be0f29` |
| Rust port | `platform/ports/basename` | 530624 | `de785d998d7464ee989599bf1ab3765495defd8cfead18d50f9b21fee602598b` |
| C port | `platform/ports/cmp` | 193160 | `6bde08fa4d1827979377ee00298e7eb78863f5b3c2779687f2e23163c9094a57` |
| Rust port | `platform/ports/cut` | 583888 | `1fd1762da444cf543949d4da6879be8f025e75e90b82a5b7d43706f4c008c74c` |
| C port | `platform/ports/diff` | 197056 | `3f169fcbc29b2c85d9583ea032bdf13bab101658b82121dca65c295abc0b33f0` |
| C port | `platform/ports/ed` | 258712 | `dd2cab5ef8e46dded67d5af263548668f4edbe3e72fc1122560952a1139a23a8` |
| C port | `platform/ports/find` | 218672 | `c4d3e8cb21c5f25e5b40e1253ac6a6dd0308876485c05cfb935b77c5741b7f75` |
| Rust port | `platform/ports/fold` | 542912 | `a164d1af0db30d4ac7b588089c246ff7cb2248d474c8a0996c24892d5450e9bd` |
| C port | `platform/ports/grep` | 225928 | `c8b96cb40d3808a37b5d7e42c071acfa7cfeec507c828b756e7b233982cd69c1` |
| C port | `platform/ports/hexdump` | 188880 | `eb5db4049bdb1c710184e90ee32380368b32793b1e450838500b0047c53b6ea5` |
| Rust port | `platform/ports/nl` | 1501416 | `49418a6a69e6cccf764028b32e10d4a962934fb3a561442d3332548143c94a4b` |
| C port | `platform/ports/od` | 197160 | `c6bc54ae93dcb93030b3f25ebed8231574b8459420f6379d3a144d95b08f386e` |
| C port | `platform/ports/printf` | 176632 | `42fc554b25717fc08ef5cb40826a0d73fc2c300eaa298cb67867e753c3fc789e` |
| Rust port | `platform/ports/rg` | 2382224 | `de8191b9a815252535929b73c689d5e485fcdc5c92b0e09ad151c21d96b567ba` |
| C port | `platform/ports/sed` | 250504 | `2313fe7ee5c683eea7a8310127ec550f112025feb670700620ed3f2f769047fd` |
| Rust port | `platform/ports/seq` | 678080 | `03da2ef0ce7a77a6f1b27b88953c94ac0fa574a8a216b06a80081d59dcc4b338` |
| C port | `platform/ports/sort` | 213656 | `be8e810da20bef4efffdda6b7a2595b90c6a85ba6ac85b006ead42e6dff97416` |
| C port | `platform/ports/tar` | 217592 | `3969d81900e1b7f51bc81082729d906451e8490ab470d54598aaa652dd5c336f` |
| C port | `platform/ports/test` | 197112 | `e49278923c88493c4d1ad8a58e3f1296614c356d3b89ff83e6630ca6b197364d` |
| Rust port | `platform/ports/uniq` | 563392 | `3d9862a031dbd2e4587f48161285367cfcc9d96ea622b360eded1fe49d75ddc7` |
| service | `platform/sshd.elf` | 967336 | `a76ae793abb04792a94369d6b5d540a4099a13078edd57cd0c940e7b70099927` |

### Media differences and how to check them

The operator ISO uses the deterministic operator-media recipe. Its only changed file in this attempt was `boot/absd-kernel`. Both kernel program-header reports match their published counterpart. All allocated section content matches except the GNU build-ID note. Operator kernel differences are LLVM-generated private symbol suffixes, their string-table offsets and the build ID. Enrollment adds its absolute auxiliary build directory in DWARF. ELF section-table offsets follow the changed metadata lengths. The compared kernel sections have identical code and data; this is not a promise that arbitrary differing kernels are equivalent.

A builder can inspect the boundaries with `readelf -Wl KERNEL`, `readelf -WS KERNEL` and `readelf -Ws --wide KERNEL`. These commands hash section bytes without rewriting the input:

```sh
objcopy --dump-section .text=/dev/stdout KERNEL /dev/null | sha256sum
objcopy --dump-section .rodata=/dev/stdout KERNEL /dev/null | sha256sum
objcopy --dump-section .data=/dev/stdout KERNEL /dev/null | sha256sum
```

Expected section hashes for the frozen pair and this source attempt:

| Kernel | Section | SHA256 |
| --- | --- | --- |
| operator | `.text` | `dcce796794446270799f4158bbcb2fc5f5500cee5bf2f9a68a45611f58f09dab` |
| operator | `.rodata` | `3d5b067d661dc08d3951a9cfc5a537af1e52e477d72b65e68173472f310c16ac` |
| operator | `.data` | `b4e5315d771d681ae711af6c9288a939fc4b95a5619545ba65ebe03aa3aac505` |
| enroll | `.text` | `f8ee2f28af47318940af22580c7f5b20c2cec4958da5238754f788110a0cdfe2` |
| enroll | `.rodata` | `089f5a1533c69ddfc036588cb1872b1c3937395270021d40ac2e97a3c413bde7` |
| enroll | `.data` | `b4e5315d771d681ae711af6c9288a939fc4b95a5619545ba65ebe03aa3aac505` |

The enrollment ISO is made by the kernel's plain `grub-mkrescue` path, rather than the deterministic operator recipe. Its bytes also depend on the clock-derived `.disk/*.uuid` and GRUB search UUID; FAT serial and directory dates; uninitialized bytes in unallocated FAT space; the GRUB translations installed on the host, including backup files; and boot-location/checksum fields that follow the ISO layout. The frozen recipe already documents these factors in `platform/scripts/media_operator.py`. They are not fixed merely by choosing the original platform checkout root.

In this attempt the EFI program became exactly equal after substituting its one UUID; the BIOS image and boot catalog became exactly equal after their decoded location and checksum fields were substituted. All 78 changed EFI FAT bytes were assigned to serial (4), dates (49), UUID (6) or unallocated space (19). Eight absent English translation/backup files account for 136 data sectors and two further directory sectors. Every other ordinary enrollment ISO file matches, apart from the kernel metadata described above. A new change outside these stated boundaries requires investigation; a different whole-image hash alone does not identify its cause.

The blank disk has the same layout, all bytes before its filesystem region and all 100 record names/nonallocation metadata. Its only changed file contents are the eight Rust ports; their sizes and subsequent block allocations account for the filesystem differences. The other 79 file contents match. Empty authorized keys and absence of a host seed were checked separately.


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
