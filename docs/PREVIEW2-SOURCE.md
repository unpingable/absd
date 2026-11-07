# Build the Preview 2 source

This recipe constructs comparison artifacts from the curated first-party
source. A successful run is not a claim of byte-for-byte reproduction.
The source manifest records the original component commits, filtered trees
and every hash-bound public adaptation. No private Git history is supplied.

| Input | Identity |
| --- | --- |
| Kernel | `919f0676eacbdd06bfa17e1da9d951fb374e3a1b` |
| Platform | `0b002f732b1d11ec503868d99896c6bd5db80757` |
| Compiled release ID | `absd-preview-2` |
| Public construction-key file SHA-256 | `499540243b79a428597369c0ec379d19f5179e1603f51d87108ca7f757897631` |

The key file is a published test public key, used only during construction
and removed from the blank disk. No private key is needed or supplied.
Operator construction uses `--no-local-login`; no local-console credential
is generated. Source-adapter checks require the exact committed component
trees and refuse changed source, unexpected files and substituted symlinks.
Only named build-output paths are excluded from that comparison.

## Environment and public inputs

Use Ubuntu 24.04 x86-64 in a disposable VM and build as an unprivileged user.
Install the packages and exact package versions in `tools/Containerfile`.
A container is optional. Restricted containers may refuse `setarch -R`.
The media profile is `platform/media/vm-operator.toml`; do not silently
substitute versions if a pinned package has disappeared. Python and all
host libraries are not fully digest-pinned. Keep at least 60 GiB free on
each filesystem holding the source and work directory.

Install the Rust toolchains and the kernel check prerequisites:

```sh
rustup toolchain install 1.95.0 1.98.0 1.94.0 --profile minimal \
  --component rust-src --component rustfmt --component clippy
rustup target add --toolchain 1.98.0 aarch64-unknown-none aarch64-unknown-none-softfloat
rustup default 1.95.0
```

The platform verifies its compiler, Cargo, standard-library source and
groff macro digests. The kernel uses Rust 1.98.0. The framebuffer host
check needs `xfonts-base`. The C kit uses the Picolibc tarball and exact
Meson/Ninja wheels from `platform/c/picolibc/PIN`; the recipe makes the
pinned venv tools available during Meson setup. C-program inputs are
`platform/userland/PIN`, patches and `PORTS.tsv`. Rust dependencies are
bound by the included locks and staging scripts. Fetch verifies archives
before the offline build. Missing inputs must fail by name.

Platform dependency preparation uses its existing core-profile
`scripts/fetch-crates.sh`, including each native port's locked workspace
and standard-library dependencies. Required workspace fetch failures stop
the network phase. Compatibility staging keeps the component's established
`platform.staged-compat` sibling directory; it is temporary build output.

For the explicit work-directory commands in this recipe, the patched SSH
dependency is staged in `WORK/staged-ssh`, outside the manifest-verified
component source. Fetch also downloads the exact `license-expression` and
`boolean.py` wheels already pinned in both components' `provenance/config.toml`,
checks their filenames and SHA-256 digests, and writes them to
`WORK/provenance-wheels`. The documented rebuild and
`check.sh [kernel|platform|all] BUILD_WORK` commands select that directory through
`ABSD_PROVENANCE_WHEELS`; no pre-existing
home cache or pip dependency resolution supplies their host checker inputs.
These staging and wheel-cache statements do not cover check without BUILD_WORK.

Rebuild and check use a fresh external Python bytecode-cache prefix.
Ordinary child interpreters inherit that policy; isolated host tools and
test fixtures receive it explicitly on their command lines. Source-local
bytecode remains an untracked input and is refused by the snapshot check.
Without a BUILD_WORK argument, check uses a fresh temporary launcher and
cache prefix instead.

The historical RC1 notice archive is fetched by its published hash as a
licence-text input, not as Preview 2 build provenance.
`docs/preview2/notices/NOTICE-INPUTS.json` binds this tree's source and
supplement texts. Additional upstream texts retain their original bytes,
URLs and revisions. The actual 18-port relink receipt and 112 consumed or
probed libc member hashes accompany that inventory. These records do not
assert every offered archive was selected or provide general legal clearance.
GRUB and Unifont are host-package inputs to the ISO; redistributing rebuilt
images retains their corresponding-source obligations. The release's boot
source archive is separate from this first-party source tree.

## Run the recipe

Start with a clean, committed clone. SOURCE denotes its absolute root;
WORK denotes the external build directory. Choose a new absolute WORK outside
the source checkout, using letters, digits, `_`, `-`, `.` and `/` only:

```sh
tools/rebuild-preview2.sh fetch /absolute/path/preview2-work
tools/rebuild-preview2.sh build /absolute/path/preview2-work
```

Fetch is the network phase. Build requests offline Cargo, compiles the
release-identified platform, builds Picolibc, the C kit, 18 C programs and
8 Rust ports, and constructs the operator and enrollment images. The C kit
uses its recorded default runtime identity; the platform uses the release
ID above. `SOURCE-ADAPTER.json` records snapshot binding and
`LINKED-NOTICES-CHECK.json` records the notice-input check.

Auxiliary disk blanking and enrollment construction set `CARGO_INCREMENTAL=0`,
matching their original producer. The operator builder has its own sanitized
environment. Leaving this setting unspecified changes the enrollment kernel's
code generation; the recipe pins it even in a fresh work directory.

`WORK/media/absd-operator.iso`, `WORK/blank/absd-operator.img` and
`WORK/enroll/enroll.iso` are the comparison media. `WORK/kernel-media`
holds the compiled kernel and init; platform ELFs and installed programs
are in `SOURCE/platform/` and `SOURCE/platform/ports/`. `WORK/REBUILT.sha256` records the
three media hashes. Compare kernel, init, platform outputs and media with
the release inputs, recording every match and explaining every difference.
Root-dependent build metadata and curated source can change digests; a
successful build alone does not explain a difference. The fresh cloud clean-room result is recorded separately; see the release notes
for its bounded correspondence and limits.

The complete suites are separate from construction and need additional
time, disk and KVM for the platform containment matrix:

```sh
tools/check.sh all /absolute/path/preview2-work
```

The current kernel suite fails at Clippy's `collapsible_if` diagnostic in
`kernel/user/src/bin/init.rs`. That source file is unchanged from the kernel
revision used for the sealed Preview 2 binaries. A completed construction is
not a kernel-suite pass. Results for later gates run separately must identify
the skipped lint step. Consult the release notes for the release disposition
and the separately recorded later-gate results.

The core profile excludes other projects' private integration sources and
reports those steps NOT_RUN. Retained-artifact comparison tests skip when
their explicit inputs are absent. An existing work directory containing
construction outputs is refused; a failure is preserved, not retried in
place. Keep source and minimal receipts, then retire occurrence-owned
temporary outputs only after their consumers and replay needs have ended.
