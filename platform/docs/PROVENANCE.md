# Provenance and licensing baseline

What third-party material this repository contains, what a distributed image
contains, what is still owed before source or binaries are released, and how
a change is checked against all of that.

Two tools with one entry point. `scripts/provenance.py` owns the
release-readiness decision: dependencies, image contents, notices, known
obligations. `scripts/spdx-check.py` owns file-level licensing metadata: it
validates `provenance.toml`, the one place that says what each tracked file
is and under what terms (docs/SOURCE-LICENSING.md). `provenance.py` runs
`spdx-check.py` and reads `provenance.toml`; it keeps no second
classification. Both use no network and build nothing. `spdx-check.py` is
Python standard library only; `provenance.py` is too, except that its licence
gate validates expressions with the pinned `license-expression` library
("The SPDX library is a policy input", below).

A passing check is a mechanical result. It is not legal clearance, and it
says nothing about whether unchanged code is original.

## Host build inputs

The developer build's host-tool list is in README.md. The cross-host build
also requires these Ubuntu 24.04 inputs:

| Package | Qualified version | Build consumer |
| --- | --- | --- |
| ninja-build | 1.11.1-2 | Picolibc's Meson backend finds `ninja` on PATH |
| groff-base | 1.23.0-3build2 | Manual renderer and the exact tree checked by `verify-inputs.sh` |
| clang | 1:18.0-59~exp2 | Provides the unversioned `clang` driver used during staging |
| libclang-rt-18-dev | 1:18.1.3-1ubuntu1 | Supplies the target builtins archive selected by clang's resource directory |

Installing the full `groff` package adds files outside the pinned renderer
tree. A host package prerequisite is distinct from shipped material: clang's
builtins library can be linked into an image, while the build driver itself
does not become an image component merely because it ran. Keep actual image
inventory and notice obligations separate from this host-tool declaration.

## Commands

    scripts/provenance.py check          # fast; run before every integration
    scripts/provenance.py full           # whole tree, notices, readiness; run for a distribution candidate
    scripts/provenance.py update         # regenerate provenance/inventory/ after a dependency or image change
    scripts/provenance.py notices operator-image --out DIR    # candidate notice bundle
    scripts/provenance.py report [--require source|binary]    # release readiness; --require fails unless ready
    python3 scripts/test_provenance.py   # the tool's own tests

`scripts/check-all.sh` runs `check` first. `scripts/spdx-check.py` can be run
on its own (`--mode release` is what a source release must pass; it fails
today because the first-party licence is pending, which is the recorded
state, not a defect). `check` compares the working tree
with the merge base on `main` (`--base REF` to choose another) and takes
about a second.

`check` prints one verdict:

| Verdict | Meaning | What to do |
|---|---|---|
| `UNCHANGED` | The change adds nothing to the baseline | Nothing |
| `NEW_REVIEW_REQUIRED` | A binary of unstated origin, attribution wording added to a first-party file, a licence needing a decision | Classify it in `provenance.toml` or decide |
| `COMPLIANCE_ACTION_REQUIRED` | A definite mechanical gap: an unclassified file or a licence tag that contradicts `provenance.toml` (from spdx-check), stale inventory, absolute path in a manifest, a tracked count that grew | Do the named fix |
| `BLOCKED` | A credential-shaped file, a removed licence file, a shipped component with no licence | Remove or restore |
| `UNKNOWN` | An input the check needs is missing (a crate source, a lock file) | Supply it and rerun |

Ordinary changes to ABSD's own code are counted and never flagged. A new
dependency under an accepted licence is listed and needs only `update`.

In a source release this directory is one component of an assembled tree
and its history is not there, so `check` has nothing to compare with. It
then checks that the directory is still the tree the release's
`SOURCE-MANIFEST.toml` names: the release's readiness was decided when it
was assembled. A changed or uncomparable directory fails, unless
`ABSD_ALLOW_MODIFIED=1` says a modified tree is being tested; changes made in
a clone are not reviewed by this check. A directory with its own `.git` is
never treated as part of a release.

## Licence policy gate

`check` and `full` end with three sections:

- `LICENCE POLICY DISTRIBUTION`: the shipped closure, with the claim's scope
  in the same line, for example:

      LICENCE POLICY DISTRIBUTION: PASS (scope: expression validity and declared-licence policy; UNVERIFIED: O2 evidence completeness, O3 identities, O4 notices, O5 composition, collector completeness, SPDX database consistency; OPEN: release-document acknowledgements; no peer given)

  `FAIL n (scope: ...)` when a declared licence breaks the policy, `NO
  CLAIM (...)` when a gating obligation is unmet. Only `PASS` exits 0.
- `LICENCE INVENTORY`: everything else the repository names, every entry
  listed with path and reason, allowed ones included. Reported for action;
  it never fails a distribution audit by itself.
- `LICENCE HOST TOOLS`: tools run on the build or test host, with their
  obligations. Using one does not touch the product; shipping one fails.

`full` also writes every entry, in every scope, to `licence-report.tsv`
beside `READINESS.md`.

The policy is the owner's (2026-10-19; a standing gate since 2026-10-29;
RC3 plan rule 7a): GPL-family software may serve as external development,
build and qualification machinery; ABSD's own code and the artifacts it
distributes are permissive only and never derived from LGPL code; GRUB is
the one separately distributed exception; derived code is never labelled
with other terms than its upstream's. Classification is by role, not by
whether a copyleft name appears somewhere in a dependency graph. Its table is
`[licence_policy]` in `provenance/config.toml`, identical in the kernel and
platform repositories except for paths:

- `allowed`: permissive SPDX terms, each commented with a user.
- `pending`: permissive terms awaiting the owner's acceptance; they fail
  the closure until decided.
- `accepted`: terms the owner accepted for one member table only, bound to
  the table, its component's version and the source's sha256, and, when they
  name `inputs`, to those inputs at their recorded sha256. An acceptance may
  be an owner `interpretation` of an unidentified text as an SPDX licence
  (with its `reasoning`, the reviewer's `caveat` and when to review it
  again); the notice then carries that licence's terms verbatim.
- `denied`: copyleft and source-available families, which name why a term
  fails (weak copyleft too).
- `exception`: only GRUB and the GNU Unifont 15.1.01 boot font, each bound
  to the component's name, version, the artifacts it may ship in and its
  source identity; for wording, to exact paths and families.
- `election`: an OR that also offers a denied licence, with the component,
  its exact `versions`, the expression, the alternative taken and the
  decision.
- `spdx_library`, `member_table`, `variant`,
  `crate_checksums`, `crate_registries`, `pin`, `host_tool`, `held` and
  `marker_exempt`, below.

The owner approved SPDX `blessing` for the pinned SQLite 3.54.0 core on
2026-11-05, including its carried clock context. The platform retains the exact
upstream dedication in `LICENSES/blessing.txt` (SHA256
`06545a6ec25fbbff6c62f205f94a35be49e38f33bea827a8cfb07d7b82e4b083`). The
amalgamation archive remains pinned to
`68e913b0fe8ec6b4e5f391c594a28872884e80d6cd042a1e50c957be46b5aa4d`.
The `sqlite-src` build files keep their separately recorded mixed terms. This
adds one allowed identifier; other licence checks and release obligations
remain in force, and it does not clear native installer/SDK issue #121.

### What a PASS claims, and what it does not

After three independent reviews (2026-10-29) the owner narrowed the gate to
what was shown sound. **A PASS claims only:**

1. **O1, expressions.** Every licence expression the claim rests on
   (provenance.toml rule fields, REUSE.toml annotations, licence tags,
   distributed components, closure crates, member-table rows, the policy's
   own terms) parses strictly with the pinned `license-expression` and
   `boolean.py` wheels, each verified by its exact sha256: unknown
   identifiers fail except `LicenseRef-`, nothing is skipped over. Cargo's
   legacy `/` for OR is read as OR for crate manifests only.
2. **Declared-licence policy.** Every licence and expression declared for
   the closure as the tool computes it (the published source tree's records
   and tags, every package the distributed artifacts' units can link, their
   declared components, the member-table rows) is allowed, elected, excepted
   or accepted by the policy, and none is denied, pending or unknown.
3. **G3, exact byte comparisons.** The pinned file hashes the tool compares
   hold (a member table's receipt pin, the table's and its bound inputs'
   sha256), and the shared tools are byte-identical to their pins.

An unmet O1 or G3 gives `NO CLAIM` and nothing is judged.

**Everything else is report-only and always listed `UNVERIFIED`**, on every
run, whether or not a problem is detected; a PASS never implies it:

- **O2 evidence completeness and lock identity**: that every lock identity
  (including several sources of one name and version inside one lock) and
  every closure input was verified. Crate archive and manifest checks run
  and their detections are listed, but are not claimed.
- **O3 identities**: that exceptions, acceptances, elections, decisions and
  paired-audit records match exactly the components shipped, and which kernel
  the operator image actually incorporates. The paired-audit kernel
  (`incorporated_commit`) and the historical `scripts/check-all.sh` default
  kernel are distinct identities; the gate lists each, and the audit of one
  says nothing about the other.
- **O4 notices**: that the notices and acknowledgements accepted terms
  require are complete and distributed.
- **O5 composition**: that a paired repository's audit covers the composed
  artifact (nested peer runs skip composition).
- **Collector completeness**: that the Picolibc member table lists every
  consumed input of every linked member.
- **SPDX database consistency**: that the wheel's licence database digest,
  SPDX list version and the boolean.py version are the recorded ones.

Owner requirements the gate does not verify are printed `OPEN` on every run
and named in the verdict line: today the Cygnus Support and University of
California, Berkeley acknowledgements that release documentation must carry.
Reporting an obligation never waives an owner requirement.

Without a peer the verdict says `no peer given`. With `--peer`, the shared
tools and paired records are compared too, but those comparisons stay
report-only (O3, O5): `check --peer` and `full --peer` make the same claim as
above. `full` still fails without a peer, through the shared-tool pairing
finding.

### The SPDX library is a policy input

Expressions are parsed and validated by `license-expression` 30.4.1 (nexB,
Apache-2.0) with `boolean.py` 5.0 (BSD-2-Clause). `scripts/provenance.py`
is therefore no longer standard-library-only: the two wheels are host
tooling, found in `$ABSD_PROVENANCE_WHEELS` or
`~/.cache/absd/provenance-wheels`, and the gate refuses to make a claim (O1)
if either is missing or differs from its pinned sha256. The library's
licence database (SPDX licence list 3.26, CC-BY-4.0 data inside the wheel)
defines which identifiers the gate recognises, so it is a versioned policy
input: `[licence_policy.spdx_library]` records the wheel version and
sha256s, the database's sha256 and the SPDX list version it embeds. The
wheel sha256s gate; the database digest, list version and boolean.py version
are compared and reported (SPDX database consistency), not gated. A change to any of them is a policy
change: `check` reports it as `NEW_REVIEW_REQUIRED` until the section's
`decision` is a new owner decision naming the new license_expression wheel
sha256.

### The shipped closure

Membership is decided from the tool's own artifact model, nothing else:

1. **The published source tree**: every tracked file. Each provenance.toml
   rule's licence fields are judged for each of its paths (an exception
   naming one path never covers another); adapted material keeps its
   upstream's terms (`license` equals `upstream-license`, ABSD's lines are
   `first-party-portion`, a `decision` does not waive a denied upstream);
   licence tags in every tracked text file, including licence texts and
   tables, and REUSE.toml annotations judged from the parsed file per path;
   copyleft wording outside the exceptions, except where `marker_exempt`
   names a record, a document that only discusses licences (its wording is
   listed in the inventory), reviewed lines of a source file with their
   exact text, or a verbatim upstream notice (below). No exemption hides a
   licence tag.
2. **Each artifact with `distributed = true`**: every package its units
   can link, every declared component, and every row of a bound member
   table naming it. **This licence closure is wider than the notice
   inventory**: the inventory (`update`, `notices`) narrows a binary to the
   dependencies its source names, the closure counts every normal
   dependency of the package. An OR offering a denied alternative needs a
   recorded election; a cross-repository component is covered by its
   paired audit.

### Member tables

A member table lists, for generated C code, each linked archive member and
every file its compilation touched, with that file's licence and use:
`consumed` (the compiler's include trace names it and the line markers
enter it) or `probe` (the dependency output names it, the preprocessor
never entered it; recorded, never judged as source). A generator that
cannot classify (a marker-suppressing option, a marker stream that
disagrees with the trace) refuses instead. The table is bound to a receipt
whose sha256 the policy pins; the receipt states the table's sha256, rows,
members and per-member counts, the source sha256, the notice's sha256 and
the sha256 of every repository file the table was generated from.

A declared component may be backed by a member table (`member_table =
PATH`): it is judged by that table's rows, per linked member, and its
`license` must be exactly the licence those consumed rows state (each
distinct expression once, sorted, joined by AND). The table must be bound,
for the component's artifact, name and version; any disagreement fails.

### Verbatim upstream notices

A `marker_exempt` entry with `upstream = { pin, pin_row, archive_sha256,
member, sha256, source_archives }` and a `decision` exempts the copyleft
wording of one exact, reviewed file carried verbatim from a pinned upstream
archive (owner decision 2026-11-01). The gate does not tell notices from
source: the guarantee is "this exact reviewed file", and adding or changing
a tuple is a reviewed configuration change, by design. It holds only when
the path is one literal repository path and neither it nor a parent
directory is a symlink; the file's bytes are `sha256`; the pin file has the
row `pin_row` with `archive_sha256`; the archive is on this machine
(`source_archives` or `$ABSD_SOURCE_ARCHIVE_<NAME>`) and `member` equals the
file byte for byte; the file is classified `imported`, declared in a
distributed component's `notice_files`, and is no pin, member table or
consumed input of one; and no tracked file other than provenance records
and documents names the path. That last check is a cheap build-input
check: it finds the path written from the repository root or relative to
the referring file, not a path assembled at run time, a glob or a tool's
search path. A byte mismatch is an unmet G3 (NO CLAIM); anything else is O3
and grants nothing, so the wording fails. Licence tags in the file are
still judged. The one tuple is Picolibc's `COPYING.picolibc`, whose AGPL-3.0
text covers only upstream `scripts/GeneratePicolibcCrossFile.sh`, which
nothing builds.

### Picolibc (platform)

Picolibc is in the operator image's closure through
`c/picolibc/PROVENANCE.tsv`, its receipt and its notice
`c/picolibc/NOTICES.txt`. `scripts/picolibc-provenance.py` regenerates
them: it checks the tarball, libc.a and kit archive against their pins;
relinks every port from its recorded inputs and requires the relinked ELF
to be the gated ELF byte for byte, taking the members from that link's own
map (a recorded map is never read); compares every linked object with the
pinned libc.a member and every build source with the tarball; and preprocesses
each linked member with its recorded command (`-E -H`). The real include trace
defines consumption. The dependency record must contain every consumed input
or the collector refuses it as incomplete; additional dependencies are probes.
A consumed host file needs its exact reviewed path and hash. An unconsumed
host probe retains its path and observed file hash with `use=probe` and empty
label/licence columns, asserting no source incorporation or licence. The
existing table reader records these probes without judging them as source.
The collector writes each consumed input's notice and the acknowledgements.
The build wrapper requests `-nostdlibinc` (`scripts/build-picolibc.sh` and
`scripts/test_target_host_headers.py`); collection independently checks the
actual recorded commands, including retained builds that recorded host probes.

### The repository inventory and host tools

Every package of every lock an artifact unit names that is not in the
closure (dormant, optional, build-time, test-only, expected-fail), each
with its licence or why it could not be read; pin rows; components of
artifacts that are not distributed; held artifacts; uncovered variants;
wording in discussion documents. Host tools are listed with their licence,
use and obligation.

### Shared tools and the counterexample corpus

`scripts/provenance.py`, `scripts/spdx-check.py`, `scripts/test_provenance.py`
and `scripts/provenance-counterexamples.toml` are one implementation in both
repositories: each repository pins exactly these in `[shared_tools.sha256]`,
`check` fails on a missing, extra or differing pin, and a peer run requires
the peer's files and pins to equal them. `provenance-counterexamples.toml`
records every reproduction an independent review used to make the gate
accept what it should not, each with the test that now refuses it.

### What it does not establish

The gate identifies licences. That a licence is known and allowed does not
show that its notices are carried or its source offered; those obligations
stay in `provenance/obligations.toml` and the notice bundle. It judges what
the records and tracked files say; it cannot find copied code whose licence
header was removed, and it takes a crate's declared licence as the crate's
terms. **A distribution candidate requires `full --peer` to print `LICENCE
POLICY DISTRIBUTION: PASS (scope: ...)`, and that PASS covers only the
claim above: the UNVERIFIED obligations and OPEN conditions must be settled
separately.**

## Records

- `provenance.toml` (repository root): what every tracked file is
  (first-party, adapted, imported, generated) and its terms. First-party
  files are `license = "pending"`: no licence has been chosen. In-tree
  third-party entries also carry what the notice bundle needs
  (`in-artifacts`, `binary-actions`, `notice-files`).
- `provenance/config.toml`: the reviewed baseline (commit, coverage, limits),
  the accepted licences for third-party dependencies in order of preference,
  and what each artifact is built from.
- `provenance/obligations.toml`: what is still owed, with a detector where
  one is possible. `open` items are listed in every readiness report;
  `resolved` items need a `resolved = "..."` statement and fail the check if
  they come back; `latent` items fire when their condition appears.
  `blocks = false` keeps an open item out of the verdict; a detector of
  `kind = "spdx"` takes its answer from `spdx-check.py --mode release`.
- `provenance/inventory/operator-image.tsv`: generated. Every package the
  locks name, whether it is linked into the image, its licence and the
  licence taken. `provenance/baseline/` holds the copy frozen at the reviewed
  baseline.

The inventory is derived from the lock files, the crates' own manifests and
`scripts/operator_image.py`, not from cargo, so it needs no staged sibling
checkouts. Exact registry roots named by `licence_policy.crate_checksums`
keep their upstream registry identity even when a build stages them inside
an ignored worktree directory. Their upstream manifest and notices come from
the registry sources; a missing upstream source remains unknown rather than
being reclassified as first-party. Local stages do not redefine upstream
licence metadata. Where a build exists, `full` compares it with the compiler's
dep-info and fails if anything compiled is missing from the inventory.

Supply original registry sources through `CARGO_HOME` or
`ABSD_CARGO_REGISTRY` (a colon-separated list of registry source directories).
This includes the original manifests of port roots staged as local packages:
their pinned archives may be cached even when Cargo has not expanded them in
`registry/src`. Use sources expanded from those verified archives, rather
than the patched build stages. A lock file does not distinguish normal,
build and development dependencies; when a manifest is missing, the tool
conservatively follows every locked edge. Benchmark crates reported through
that fallback are unknown inputs, not proof that a benchmark was linked.
Restore the original manifests before interpreting the closure or updating
its inventory. The installed-program workspace check also keeps `absd-sftp`
in the SSH package's unit rather than the root command package's unit.

### Notice destinations

A C-port unit may list common `notice_files`, or map each pinned upstream
identity to its own list. The current userland unit maps `sbase-0.1` to
`userland/sbase.LICENSE` and `toybox-0.8.15` to `userland/diff/LICENSE`.
The Toybox diff and hexdump notice copies are byte-identical. Each component
receives its selected upstream's notice, and a missing map entry refuses
inventory construction. A PIN version change needs the matching map key;
it cannot silently inherit another version's notices. The inventory's
columns stay unchanged.

Two distinct source files must not map to the same output pathname, even
when their current bytes happen to match. Notice generation refuses that
collision before overwriting the first file and does not write a successful
NOTICES.md or inventory.tsv. A partial directory from that failed attempt
is not a valid bundle. Repeated use of the same source pathname is permitted;
the Rust toolchain rows share their notice set this way. Directory notices
use the same check for every copied file.

The rust-src 1.95.0 toolchain also contains compiler_builtins 0.1.160's own
`library/compiler-builtins/libm`, whose manifest version is 0.2.16. This
names that toolchain source; its contents differ from the registry
libm-0.2.16 crate. Its Sun notices are an additional source to name alongside
the separately fetched crate. Only the linked compiler_builtins row gains
this origin note; other toolchain and not-built rows retain the base origin.
That origin does not establish which math functions were selected by a linker or make
the toolchain's general COPYRIGHT-library.html a complete per-file notice
collection. The RC1 additive notices correction carries the shared Sun
permission text; future notice generation must retain that text and name
both sources. This change does not alter the published RC1 archive.

The generic generator's current source cache lacks texts for the following
four inputs. They are named gaps in that cache, not new claims that the
published RC1 notices omit them:

| Input | Present in RC1 | Published coverage |
| --- | --- | --- |
| base64-simd 0.8.0 | Yes, linked port dependency in the frozen operator inventory | Original notices archive's base64-simd-0.8.0/LICENSE |
| fluent-langneg 0.13.1 | Yes, linked port dependency in that inventory | Original notices archive's fluent-langneg-0.13.1/LICENSE-APACHE and LICENSE-MIT |
| intl_pluralrules 7.0.2 | Yes, linked port dependency in that inventory | Original notices archive's intl_pluralrules-7.0.2/LICENSE-APACHE and LICENSE-MIT |
| vsimd 0.8.0 | Yes, linked port dependency in that inventory | Original notices archive's vsimd-0.8.0/LICENSE |

The boot font is GNU Unifont 15.1.01, present at
`/boot/grub/fonts/unicode.pf2` in both RC1 ISOs. The file is 2,411,806 bytes, SHA-256
`662eb86fc1ea89635e4bba8413590b79eb714ade5a2b5a5aa3dc5cf5f53a4463`,
as recorded in RC1's NOTICES.md and media binding. The original base notice
archive is SHA-256
`9d2760276584cebce0dac55cdcc9a5cb75618497e8720c26bd5e45c4960eae4b`.
The later additive correction is not needed for these texts. It closes
different named gaps. The four Rust presence statements use dependency
inventory classification, not a per-symbol linker proof. A fresh generic
bundle must still obtain its missing source texts or retain those explicit
findings; the passing generator tests do not establish notice completeness.

### Versioned boot-font election

The owner elected **OFL-1.1** for that exact Unifont font on 2026-10-19.
The supplied `unifont 1:15.1.01-1build1` source package contains upstream
15.1.01's `COPYING`, which offers OFL-1.1 for its font files; the two listed
jiskan16 exceptions are public domain. The precompiled font's own copyright
also states the OFL-1.1 alternative. This decision does not rely on terms for
a newer Unifont release.

Converting that source archive's
`font/precompiled/unifont-15.1.01.pcf.gz` with `grub-mkfont 2.12-1ubuntu7.3`
reproduces the exact font bytes extracted from both original RC1 ISOs.
`provenance/boot-font/unifont-15.1.01.NOTICE` preserves the font's copyright
property verbatim, including its original alternatives; `LICENSES/OFL-1.1.txt`
is the exact text supplied in that version's `OFL-1.1.txt`. The artifact
configuration and generated inventory record the elected OFL-1.1 alternative
and collect both files. These source notices must accompany future font
distribution. A changed font requires its own source and eligibility check.
The frozen audit-baseline TSV retains its historical unverified row; it is
not the current generated inventory and is not rewritten by this election.

This font election does not apply to Unifont's GPL program source or GFDL
documentation. Modified-font and reserved-name conditions remain applicable.
The original RC1 notices already contain the versioned `COPYING`, `README`
and OFL text. They and the published RC1 media remain immutable; this record
applies from the next notices and source revision onward. No compiler, media
recipe, boot font, dependency pin or qualification criterion changes.

### RC2 notices correction, 2026-10-29

The RC2 licensing assessment (platform `c3cc94ab`, kernel `101c61d8`) found
the operator-image notices incomplete; it found no binary that has to change.
This correction is notice and inventory metadata only:

- The Unifont election above, which `c3cc94ab` did not contain, is carried
  forward unchanged.
- Intel's BSD-3-Clause header from kernel `src/i219.rs` is copied verbatim to
  `provenance/kernel-notices/` and declared as an operator-image component,
  so the generated notices reproduce it. The kernel is unchanged; its own
  obligation `I219-ON-MERGE` stays open in the kernel repository.
- Picolibc 1.8.12 and clang's compiler-rt builtins are declared as
  operator-image components for the C ports. Picolibc's `COPYING.picolibc`
  is carried verbatim from the pinned archive. The retained link maps of the
  RC2 public reconstruction select Picolibc `libc.a` members in all twelve
  ports and no compiler-rt member; compiler-rt is listed conservatively as a
  compiler input.

No compiler, linker input, media recipe, boot font, dependency pin or
qualification criterion changes. On the latest integration line the
Picolibc component takes its licence from `c/picolibc/PROVENANCE.tsv`
(above) and `COPYING.picolibc` is a verbatim upstream notice exemption.

## Bringing in existing code

- Public specifications may be implemented freely. Cite the specification.
- Permissively licensed source may be adapted. Keep its copyright notice and
  licence in the file, and add a `provenance.toml` rule naming the upstream,
  the revision and the licence (`class = "adapted"` or `"imported"`).
- Copyleft source (GPL, LGPL, AGPL, MPL and similar) is not incorporated
  into ABSD, as code or as a dependency. The licence policy gate fails on it
  whatever its label, and a `decision` on its rule (or under
  `[policy.decisions]`) does not change that; only the owner adds an
  exception to `[licence_policy]`. Reading it to learn how
  hardware or a protocol behaves is allowed; say so in the commit when it
  shaped the code.
- Reading source is not copying it. Copying, translating or closely
  following it is adaptation and gets a declaration.
- If you cannot say where something came from, classify it `unresolved`
  with the reason. Unknown provenance is reviewed, not hidden.
- Do not add licence identifiers or copyright lines to first-party files
  while the licence is pending.
- "Clean-room" may be claimed only for work done under a documented
  separation procedure. None has been used so far.
- A new dependency: add it, run `update`, commit the inventory change. If its
  licence is not on the accepted list the check asks for a decision.

## What the baseline does and does not establish

The baseline is the tree reviewed on 2026-10-10 (`config.toml` names the
commit). That review attributed the dependency, vendored and patched material
to its upstreams and traced what is shipped; the rest of ABSD's own code was
searched for markers only,
and no platform file was compared with any upstream. It was done by AI
sessions. `full` prints these limits with every report, with the number of
files unchanged since the baseline at each level of coverage and the number
changed since, which no review has covered.

## Before a release

`report --require source` and `report --require binary` list what blocks each
and fail until the list is empty. Today both are `NOT_READY`: no licence is
chosen for ABSD's own code, images carry no third-party notices, the ISO
carries GRUB and a font with their own terms, and the build depends on paths
and private checkouts on the development machine. Choosing a licence and the
questions marked for counsel are the owner's; the tool only tracks them.

The notice bundle is a candidate. It collects the licence texts the shipped
components carry and lists, separately, what collecting texts does not
satisfy: corresponding source for GRUB, texts that must be fetched from
upstream, modified upstream files.

## Limits

- Copied code with its header removed is not detectable by any check here.
- Documents (`*.md`, `docs/`), manual pages and the readiness records are
  not scanned for attribution wording; everything else is, and "adapted
  from" or "ported from" about ABSD's own code will need rewording. Binaries
  under the directories `scan.binary_ok` names are accepted as
  project-generated; a changed binary is not flagged.
- A file with no licence wording moved out of a vendored directory into
  first-party source passes.
- A third-party file that is added or changed needs its `provenance.toml`
  rule touched in the same change; a new rule with new files is accepted as
  recorded and shown as a note, not reviewed by the tool.
- Obligations of kind `counsel` and `note` never block a readiness verdict;
  the website verdict only reflects the site notes recorded here.
- `provenance/baseline/` is the inventory of the baseline tree as the current
  tool computes it; labels of unshipped rows follow the tool, the shipped set
  is the baseline's.
- Only the locks and image lists `provenance/config.toml` names are
  inventoried. A lock file it does not read is flagged; a downloading build
  script is not. The test-matrix images and the release
  directory's extra programs are not inventoried crate by crate.
- The `/bin` command inventory counts the dependencies each installed
  binary's sources name; `full` cross-checks ports and sshd against compiler
  output when a build exists, and only notes the commands.
- The GRUB version, its modules and the font on an ISO come from the build
  host and are not pinned; a notice bundle is tied to an inventory hash, and
  nothing re-verifies an old bundle.
- `check` compares with the merge base on `main`; on `main` itself it sees
  only uncommitted work, and `full` is the whole-tree check.
- Accepted counts and exemptions do not expire; changing them shows in
  `check` output as a records change, and in review.
- The private-name scan needs `~/.config/absd/private-patterns`, which is
  never committed. Without it that scan reports itself as not run; no check
  passes or fails because of it.
- Results that need the crate cache, the toolchain's sources and docs, or
  the host's GRUB package say `UNKNOWN` or list the text as missing when
  those are absent.
- `scripts/provenance.py`, `scripts/spdx-check.py` and
  `scripts/test_provenance.py` are the same files in the kernel and platform
  repositories (since 2026-10-29), with repository-specific behaviour only in
  `provenance/config.toml`; `[shared_tools]` pins their sha256 and `check`
  fails on drift.


## Document-enabled operator notices

The default `operator-image` inventory and notice command keep their existing
behavior. `provenance.py update` does not select the optional HTTPS command.
For a release built with `ABSD_HTTPS_DOCUMENT=1`, generate its separate bundle
from the exact clean source used for that release:

```sh
python3 scripts/provenance.py notices operator-image-document \
  --document-release "$RELEASE_DIR" \
  --document-build-receipt "$DOCUMENT_BUILD_RECEIPT" \
  --document-deps "$DOCUMENT_TARGET_DEPS" \
  --out "$DOCUMENT_NOTICE_DIR"
```

`DOCUMENT_BUILD_RECEIPT` is the actual JSON receipt emitted by
`build-native-tls-fixture.py --document-app`. `DOCUMENT_TARGET_DEPS` contains
that build's `tls/target/x86_64-unknown-absd/release/deps/*.d`, retained together
with the receipt and executable. Preserve the existing `tls/tree/ring`
staging link, `STAGE.json`, `STAGED-FILES.json` and exact patched sources.
Supply the pinned registry sources through the existing `CARGO_HOME` or
`ABSD_CARGO_REGISTRY` setting; licence terms and texts are read from those
sources. They are not inferred from dependency names or pin labels.
For ring, the pinned upstream archive must also be expanded in that registry
source input even though compilation uses the patched staging tree. Expanding
it after a build supplies notice metadata and texts only; it does not establish
compiler consumption. The original native dep-info, patched-stage receipt and
source hashes remain authoritative. Cargo's `tree/ring/` dep-info spelling is
accepted only when `tls/Cargo.toml` declares that exact patch path and the
staging link resolves to the same receipt-verified patched tree. Unrelated
paths with a matching suffix are refused.
Dependency rules are checked on their source-side entries; output target paths
do not establish source identity. Relative TLS library and command entries must
match their exact declared Cargo entry paths within the selected source tree.

Selection refuses before writing output when the release does not declare
the app, its ELF differs from the manifest or native build receipt, source,
lock, target, patched ring or staged standard-library identities differ, a
compiler input cannot be resolved, or compiler dep-info differs from the
resolved application plus standard-library compiler-unit closure. Each path, toolchain and
registry package must have its own manifest-derived Cargo target and exact
source path; nested toolchain directories and explicit library target aliases
are resolved from those manifests. Unexpected target outputs are refused. The
document inventory labels these rows `compiler-input`: compilation and Cargo
unit dependencies do not establish final ELF code membership. The observed
standard-library compiler roots include `panic_unwind` and `proc_macro`; the
latter brings `rustc-literal-escaper`. Other-target packages remain excluded. The selected
inventory includes the exact command hash and the TLS dependency unit;
`DOCUMENT-COMPOSITION.json` binds the manifest, native receipt, compiler
package set, per-crate source manifest hashes, dep-info identities and ring
stage. Available Cargo fingerprints are retained as compiler-unit observations,
not evidence of final code extraction. Missing fingerprints are reported; they
do not replace the complete dep-info census. The native builder records the complete target dep-info file set,
hashes and lengths in `application.target_dep_info`; the consumer requires
that exact set. A final missing-text result from any base-image or toolchain
component fails the document command and leaves its incomplete notice report
without a composition success receipt. Default notice behavior is unchanged. The bundle also carries the
existing default image notices and the ring adaptation notices.

Toolchain notice paths come from the actual `ABSD_REAL_RUSTC` in the native
receipt, not the invoking user's home. A missing compiler field or symlink
in any selected toolchain/notice path component refuses document selection. The observed Rust 1.95 `proc_macro`
manifest lacks a Cargo license declaration. For that exact manifest, staged
standard-library tree, compiler and `COPYRIGHT-library.html` identities only,
the inventory records the upstream root-scope Apache-2.0 OR MIT declaration
as derived metadata, explicitly not Cargo-declared. An applicable exception,
changed identity or missing text refuses this derivation. Existing license
elections and all base-image notice gates remain unchanged.

Source-only fixtures can exercise dependency resolution and compare copied
upstream texts. They do not establish the actual compiler closure or accept
a document-enabled shipping artifact. Missing build/dep-info inputs remain a
release prerequisite. The final release's collector and independent review
must establish their custody; a directory of unbound files is not a native
qualification result. Other distribution obligations reported by the existing
notice generator remain applicable.


Historical App A receipts emitted before `application.target_dep_info` was
introduced cannot satisfy this selected-artifact check. Their earlier native
results keep their original scope. Generate the document-enabled shipping
bundle only from a final candidate built with the corrected native builder;
do not add the field to an old receipt or relabel historical outputs.
