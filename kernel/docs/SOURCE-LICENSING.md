# Source licensing metadata

How files in this repository say where they came from and under what terms.
It follows SPDX identifiers and the REUSE layout, with one deliberate gap.

**First-party ABSD source is licensed under Apache-2.0.** The owner decided
this on 2026-10-10: Apache-2.0 only, for the kernel, platform, tools and
tests. Third-party material keeps its own terms, and separately maintained
projects (Pulse, AG, NQ, Nightshift) keep theirs. `provenance.toml` records
the licence per file, the root `LICENSE` and `LICENSES/Apache-2.0.txt` carry
the text, and one `REUSE.toml` annotation covers first-party files.

First-party files carry no header yet. Whether they carry a copyright line,
and what it reads, is not decided; what copyright subsists in code written
by AI systems is an open question the decision does not settle. Adding
headers is deferred until after the next full qualification, because a
header shifts line numbers that built programs embed and changes files
other checks pin by digest. This repository does not pass `reuse lint` (no
copyright lines) and does not claim REUSE compliance.

An SPDX identifier is a statement about a file's licence. Write one only
when the licence is established by evidence you can point to: upstream's own
licence file or manifest, or the owner's recorded decision. Git authorship,
a neighbouring file's header, and the licence of a crate a file resembles
are not evidence.

## Where the metadata lives

| Place | Holds |
| --- | --- |
| A header in the file | The normal form for an ordinary source file whose licence is established. Upstream's own header, kept exactly as it arrived, is this case. |
| `REUSE.toml`, or a `<file>.license` sidecar | Files that cannot or should not be edited: imported upstream files, content-pinned inputs, generated files, binaries. |
| `LICENSES/<id>.txt` | The text of every identifier used above. Nothing else. |
| `provenance.toml` | The class of every tracked file, upstream origin and terms where there are any, and `pending` for anything whose licence is undecided. |

Crates pulled from the registry are not annotated, here or in their own
sources. Their licences and notices belong to `scripts/provenance.py`'s
dependency inventory and generated notice set.

## Keys the readiness tool reads

`scripts/provenance.py` reads `provenance.toml` through this check's rule
matching and adds no classification of its own. A few optional keys on a
rule are for it alone; this check ignores them, and a misspelt key is
ignored silently by both:

| Key | Meaning |
| --- | --- |
| `notice-files` | Upstream licence or notice files in this tree that must stay present and are copied into notice bundles. |
| `in-artifacts` | The artifacts (named in `provenance/config.toml`) that contain this material; it is listed in their notice bundles. |
| `binary-actions` | What a binary containing the material owes beyond carrying a text. |
| `decision` | Who decided, when and why, for material whose upstream terms are not on the accepted list. |
| `kind = "test-key"` | The one accepted reason for a credential-shaped file: a fixture key, with a comment saying why it is not live. |

Given `--base`, this check also judges files not yet added to the index,
since they are part of the change being judged. A new file outside every
classified root therefore fails until a rule covers it.

## The five kinds of file

Every tracked file matches one `[[files]]` rule in `provenance.toml`. The
last matching rule wins. Roots are named one by one, so a new top-level
directory is unclassified until someone says what it is.

| Class | What it is | What you do |
| --- | --- | --- |
| `first-party` | Written for ABSD, by a person or a model session, from specifications and ABSD's own interfaces. | Nothing in the file: `provenance.toml` gives `license = "Apache-2.0"` and the `REUSE.toml` annotation carries it. No copyright line, and no `license` field in a new `Cargo.toml`, until the owner settles the copyright line. |
| `adapted` | ABSD work that reuses someone else's source: a port, a translation, a patch against their file. | Record `origin` (project, file, revision) and `upstream-license`. Keep upstream's notice word for word. See below for the `license` field. |
| `generated` | Written by a tool. | Record `generator`. Do not edit by hand. If the input is third-party, record `origin` and `upstream-license`. Licensing follows the inputs. |
| `imported` | Someone else's file, kept as it was. | Do not add a header. Annotate in `REUSE.toml` with upstream's own identifier and copyright line (omit the line if upstream states none). Keep upstream's licence files. Record `origin` with version and hash. List any local change in `first-party-portion` and beside the import. |
| `unresolved` | The origin, or a licence statement already in the file, cannot yet be relied on. | Record `reason`. Do not guess, and do not delete the statement. |

### Adapted source

Two shapes, decided by whether upstream's terms require its notice to stay
with the code.

- **The notice travels in the file** (a BSD or MIT source ported into an
  ABSD file). Upstream's header stays at the top unchanged, including any
  SPDX line inside it. Set `license` to upstream's identifier and
  `first-party-portion = "Apache-2.0"`, and add the text to `LICENSES/`. That
  records upstream's terms on what came from upstream and ABSD's on its own
  part.
- **The file is a patch**, whose context lines are upstream's and whose
  added lines are ABSD's. Set `license = "Apache-2.0"` (the added lines) and record
  `upstream-license`. No identifier goes in the patch.

Say in the file what was adapted and from which revision. Never remove or
reword an upstream copyright or licence notice, and never rewrite code only
to shed one.

### What is still open

The copyright line (see the top of this file). When the owner settles it,
it is recorded here with its date, and headers are added by script in one
change.

## The check

    make spdx-check                          # development mode
    scripts/spdx-check.py --mode release     # for a source release
    scripts/spdx-check.py --base main        # what this change brings in
    scripts/spdx-check.py --json             # full report

It reads tracked files (and, with `--base`, files not yet added), takes under a second, and reports five kinds
of finding.

| Finding | Meaning | Development | Release |
| --- | --- | --- | --- |
| `missing-metadata` | No rule classifies the file; or a rule states a licence that no header, sidecar or annotation carries; or a used identifier has no text in `LICENSES/`. | fails | fails |
| `unknown-licensing` | `pending` or `unresolved`: recorded, undecided. | passes | fails |
| `conflict` | Two sources disagree: a header against the inventory, or any licence declaration (including a `Cargo.toml` `license` field) on a file the inventory calls pending. | fails | fails |
| `accepted-exception` | One of the above that an `[[exceptions]]` entry names, with a reason, who decided and when. | passes | passes |
| `new-obligation` | With `--base`: imported or adapted material added or changed, a licence text new to the repository, a changed lock file, or attribution wording added to a pending file. | reported | reported |

Ordinary first-party work passes without touching any of this: a new file
under an existing first-party root is already classified as Apache-2.0. The
check fails a development commit only when the commit itself adds something
unclassified or contradictory. `--fail-on-new` turns new obligations into
failures for a caller that wants that.

`conflict` here means the metadata disagrees with itself. Whether two
licences can be combined in one binary is a dependency question and is
`scripts/provenance.py`'s (docs/PROVENANCE.md).

An exception is the owner's to grant. Do not add one to make the check pass.

## For the release-readiness tooling

Run `scripts/spdx-check.py --mode release --json` in each repository and
read `pass`, `counts` and `findings` (schema `absd-spdx-check/1`; exit 0
pass, 1 fail, 2 unusable configuration). Add `--base <last released
revision>` to get the `new-obligation` list for the notice review.

Take in-tree third-party material from the `adapted`, `imported` and
`generated` rules of `provenance.toml` (`origin`, `upstream-license`,
`upstream-notice`). The lock files do not show it. This check does not read
dependency licences or build notices, and does not duplicate that work.

Release mode passes only when nothing is `pending` or `unresolved`. A failure
there is the correct result, not a defect to route around.

## Open in this repository

<!-- REUSE-IgnoreStart -->

- No first-party licence decision is open. The copyright line is.
- `fbcon/src/font8x13.rs`: the glyph bytes are X.Org `font-misc-misc`
  8x13, whose COPYING reads "Public domain font.  Share and enjoy." The
  surrounding file is written by `scripts/font-8x13.py`. Recorded as
  generated, Apache-2.0 for the surrounding file; the glyph bytes are not
  relicensed and the file is not declared public domain.
- The I219 driver (`src/i219.rs`, from `lane/native-hardware-a1-20261009`)
  is adapted from Intel's BSD-3-Clause shared code in FreeBSD and keeps
  Intel's header. The owner decided on 2026-10-10 to keep it with that
  attribution, and `provenance.toml` carries the rule for `src/i219.rs`.
  The licence text is at
  `LICENSES/BSD-3-Clause.txt`, added by the merge `7aaed9e`.
  `i219_device.rs`, `i219_pci.rs` and `i219_ring.rs` are first-party by
  derivation: a textual comparison found nothing from FreeBSD or Linux in
  them and they follow this kernel's own e1000 driver. They were written in
  the same session with the FreeBSD files open, which is recorded, not
  resolved, by that comparison. Any image containing the driver must
  reproduce the Intel notice.

<!-- REUSE-IgnoreEnd -->
