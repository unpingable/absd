# How a source release is made

ABSD is developed in separate repositories, one per component. This
repository is assembled from them. Its `main` branch moves only when a
release is made, and each release is one commit.

## What a release is

A release is the tree produced by the assembly tool (`tools/assemble.py`,
with `tools/assembly.toml`) from:

- one exact commit of each component, named in `SOURCE-MANIFEST.toml`;
- the list of files left out of each component, also in the manifest;
- any explicit public-source sanitation edits, with input/output file
  hashes, exact line preconditions and reasons;
- the files written for this repository (this file, the top-level README,
  `tools/`, `docs/README.md`).

No other component changes are made. For each component the manifest records the Git tree
id of its directory here, so anyone can confirm what they have:

    git rev-parse HEAD:kernel        # equals the manifest's kernel `tree`

For `kernel/` and `platform/` it differs from the development commit's tree
by the excluded files, which are development records (campaign logs,
review transcripts, receipts recorded on the development host) and, in the
platform, the patches and manifests that carry other projects' source for
the extended integration profile, and by the recorded sanitation edits.
When edits exist, `filtered_tree` names the unchanged subset before them;
`tree` names the final public component. An input, line or output hash
mismatch refuses the assembly. The removed private text is not copied
into the public instructions. See `docs/RC1-SOURCE.md` for this candidate's
specific changes and reconstruction limits.

Assembling the same configuration twice gives the same tree. That is a
statement about source. Whether builds of that source are bit-for-bit
reproducible is a separate question; see the README for what was measured.

## What is checked before a release

The assembly tool reports six things separately and a release needs all of
them:

1. **Pins.** The effective public build recipe names the exact component
   pair assembled. A stale development default is disclosed separately;
   this check is not evidence that qualification ran on the public tree.
2. **Private material.** No development-machine paths, host names, private
   addresses, internal tracker identifiers or credentials in the tree, apart
   from findings accepted in the configuration with a written reason.
3. **Source readiness.** Each component's own `scripts/provenance.py report
   --require source` must pass: licences, notices and known obligations.
4. **Reproducible assembly.**
5. **Linked-input notices.** The configured checker must run against the
   exact base archive named by `ABSD_RC1_BASE_NOTICES`, with a successful
   structured receipt. Missing input, missing notice coverage or a failed
   checker keeps publication readiness from clearing. The receipt is
   separate from the component source-readiness reports.
6. **Nothing held.** The configuration lists reasons a release is held that
   no check can see; the list must be empty.

For RC1 and any successor using these C-build inputs, the linked-input
notice check in `docs/RC1-SOURCE.md` is also required before preparing
release media/notices. It augments the Cargo inventory with the C kit,
upstream driver notices and retained per-file notices. Input fingerprints
that change require a fresh inventory audit; an old pass never clears them.

Those six say the tree is what it claims to be and safe to publish. They
say nothing about whether it works. That is qualification: the assembled
tree is built, booted and tested from a clean clone in a clean environment,
following only the README. Whatever part of that was not run on a release
is listed in its manifest under `not_run` and at the top of its README, and
is never described as passed.

A tree that has not passed carries a file named `NOT-FOR-PUBLICATION.md`
saying why, from the first moment of its assembly. The tool commits only
the tree its last build produced, and never commits one that has not
passed to `main`.

## Promoting development work

A change reaches a release by being accepted in its component's development
repository under that repository's own checks, and then by a later release
naming a later commit. There is no synchronisation between releases and no
partial update of one file.

Releases are identified by an id in the manifest and a tag of the same name.
Release artifacts are identified by digest; they are not signed.
