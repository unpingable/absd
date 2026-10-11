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
classification. Both are Python standard library, use no network and build
nothing.

A passing check is a mechanical result. It is not legal clearance, and it
says nothing about whether unchanged code is original.

## Commands

    scripts/provenance.py check          # fast; run before every integration
    scripts/provenance.py full           # whole tree, notices, readiness; run for a distribution candidate
    scripts/provenance.py update         # regenerate provenance/inventory/ after a dependency or image change
    scripts/provenance.py notices kernel-image --out DIR    # candidate notice bundle
    scripts/provenance.py report [--require source|binary]    # release readiness; --require fails unless ready
    python3 scripts/test_provenance.py   # the tool's own tests

`make check` runs `check` first (`make provenance-check` adds the tool's own
tests; `make provenance-full` runs `full`). `scripts/spdx-check.py` can be run
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
- `provenance/inventory/kernel-image.tsv`: generated. Every package the
  locks name, whether it is linked into the image, its licence and the
  licence taken. `provenance/baseline/` holds the copy frozen at the reviewed
  baseline.

The kernel has no registry dependencies. Its inventory is the lock file
plus the components `config.toml` declares for a bootable image: the Rust
core libraries, the console font, and what `grub-mkrescue` adds. A served
image also embeds platform programs; their inventory is in the platform
repository.

## Bringing in existing code

- Public specifications may be implemented freely. Cite the specification.
- Permissively licensed source may be adapted. Keep its copyright notice and
  licence in the file, and add a `provenance.toml` rule naming the upstream,
  the revision and the licence (`class = "adapted"` or `"imported"`).
- Copyleft source (GPL, LGPL, MPL and similar) is not incorporated into
  ABSD's own code without an explicit decision, recorded as `decision = "..."`
  on its `provenance.toml` rule (or under `[policy.decisions]` for a
  dependency). Reading it to learn how
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
commit). That review compared nine driver files textually with the Linux and
FreeBSD drivers, inspected the head and structure of the loaders, boot code
and font, sampled the documents, and searched everything else for markers
only. It was done by AI sessions. `full` prints these limits with every report, with the number of
files unchanged since the baseline at each level of coverage and the number
changed since, which no review has covered.

## Before a release

`report --require source` and `report --require binary` list what blocks each
and fail until the list is empty. Today both are `NOT_READY`: no licence is
chosen for ABSD's own code, images carry no third-party notices, every ISO
carries GRUB and a font with their own terms, and the documents and history
hold development-machine detail. Two unmerged branches (an Ethernet driver
adapted from BSD-licensed code, and the xHCI work) have obligations that
become active when they merge; `obligations.toml` holds them as `latent`. Choosing a licence and the
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
- Only what `provenance/config.toml` names is inventoried; a lock file it
  does not read is flagged, a downloading build script is not. Platform
  programs embedded in a served image are inventoried in the platform
  repository, not here.
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
- `scripts/provenance.py` and `scripts/spdx-check.py` are kept identical in
  the kernel and platform repositories by hand.
